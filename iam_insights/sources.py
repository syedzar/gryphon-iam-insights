"""Data sources: where the users, registration details and sign-ins come from.

Two implementations share one interface:

* MockSource  reads the synthetic JSON files in data/mock/.
* GraphSource calls the real Microsoft Graph REST API with your own token.

Every method returns plain Python data (lists of dicts in Graph's format), so
the analysis code never needs to know which source it's talking to.
"""

import json
import sys
import time
from pathlib import Path
from typing import Callable, Protocol

import requests

from iam_insights import config

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 3  # how many times to retry after an HTTP 429 (rate limited)

# Fields we ask for on GET /users. signInActivity is only returned if selected.
USER_FIELDS = ",".join([
    "id", "displayName", "userPrincipalName", "mail", "accountEnabled", "employeeType",
    "department", "createdDateTime", "employeeLeaveDateTime", "signInActivity",
])

# Which Graph permission each endpoint needs, used in friendly 403 messages.
REQUIRED_PERMISSION = {
    "/users": "User.Read.All and AuditLog.Read.All",
    "/reports/authenticationMethods/userRegistrationDetails": "AuditLog.Read.All",
    "/auditLogs/signIns": "AuditLog.Read.All",
    "/me": "User.Read",
    "/me/authentication/methods": "UserAuthenticationMethod.Read",
}
ADMIN_ONLY = {"User.Read.All and AuditLog.Read.All", "AuditLog.Read.All"}


class DataSource(Protocol):
    """The interface both sources follow."""

    name: str

    def get_users(self) -> list[dict]: ...
    def get_registration_details(self) -> list[dict]: ...
    def get_sign_ins(self) -> list[dict]: ...
    def get_me(self) -> dict: ...
    def get_my_auth_methods(self) -> list[dict]: ...


def _graph_error_message(response) -> str:
    """Pull Graph's own error text out of a failed response, e.g. ' (Request_BadRequest: ...)'.

    Graph errors look like {"error": {"code": "...", "message": "..."}}. If the
    body isn't JSON in that shape, return an empty string.
    """
    try:
        error = response.json().get("error") or {}
    except (ValueError, AttributeError):
        return ""
    code, message = error.get("code"), error.get("message")
    if not isinstance(code, str) and not isinstance(message, str):
        return ""
    return f" ({': '.join(part for part in (code, message) if isinstance(part, str) and part)})"


class GraphError(Exception):
    """A Graph call failed in a way we can explain to the user (401, 403, ...)."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Mock
# ---------------------------------------------------------------------------

class MockSource:
    """Reads data/mock/*.json and returns the "value" list from each file."""

    name = "mock"

    def __init__(self, folder: Path | str = config.MOCK_DIR):
        self.folder = Path(folder)

    def _load(self, filename: str) -> list[dict]:
        with open(self.folder / filename, encoding="utf-8") as f:
            return json.load(f)["value"]

    def get_users(self) -> list[dict]:
        return self._load("users.json")

    def get_registration_details(self) -> list[dict]:
        return self._load("userRegistrationDetails.json")

    def get_sign_ins(self) -> list[dict]:
        return self._load("signIns.json")

    def get_me(self) -> dict:
        """Pretend the first mock user is the person signed in."""
        return self.get_users()[0]

    def get_my_auth_methods(self) -> list[dict]:
        """Turn the first user's registration record into /me/authentication/methods shape."""
        me = self.get_me()
        details = next(d for d in self.get_registration_details() if d["id"] == me["id"])
        # Map report method names to the @odata.type used by /me/authentication/methods.
        odata_types = {
            "microsoftAuthenticatorPush": "microsoftAuthenticatorAuthenticationMethod",
            "microsoftAuthenticatorPasswordless": "microsoftAuthenticatorAuthenticationMethod",
            "passKeyDeviceBound": "fido2AuthenticationMethod",
            "fido2": "fido2AuthenticationMethod",
            "softwareOneTimePasscode": "softwareOathAuthenticationMethod",
            "mobilePhone": "phoneAuthenticationMethod",
            "email": "emailAuthenticationMethod",
        }
        methods = [{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "password"}]
        for i, name in enumerate(details["methodsRegistered"]):
            methods.append({"@odata.type": f"#microsoft.graph.{odata_types[name]}", "id": f"mock-{i}"})
        return methods


# ---------------------------------------------------------------------------
# Real Microsoft Graph
# ---------------------------------------------------------------------------

class GraphSource:
    """Calls Microsoft Graph with plain HTTPS requests and a bearer token.

    Only /me and /me/authentication/methods work with a normal student account.
    The tenant-wide reports need admin permissions, so if Graph refuses them we
    print a friendly message and fall back to the mock data instead of crashing.
    """

    name = "graph"

    def __init__(
        self,
        token: str,
        base_url: str = GRAPH_BASE_URL,
        session: requests.Session | None = None,
        fallback: DataSource | None = None,
        sleep: Callable[[float], None] = time.sleep,
        notify: Callable[[str], None] | None = None,
    ):
        if not token:
            raise GraphError("No GRAPH_TOKEN set. Add it to .env, or use DATA_SOURCE=mock.")
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        self.fallback = fallback or MockSource()
        self.sleep = sleep  # injectable so tests don't actually wait
        self.notify = notify or (lambda msg: print(msg, file=sys.stderr))
        self.messages: list[str] = []  # every friendly message, for the dashboard

    # -- low-level HTTP -----------------------------------------------------

    def _request(self, url: str, path: str, params: dict | None = None) -> dict:
        """GET one URL, retrying on 429 and translating 401/403 into GraphError."""
        for attempt in range(MAX_RETRIES + 1):
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 429 and attempt < MAX_RETRIES:
                # Graph tells us how long to wait in the Retry-After header (seconds).
                wait = float(response.headers.get("Retry-After", 2 ** attempt))
                self.sleep(wait)
                continue

            if response.status_code == 401:
                raise GraphError(
                    "Graph returned 401 Unauthorized: the token is missing, invalid or expired "
                    "(tokens last about an hour). Get a fresh one from Graph Explorer.",
                    401,
                )
            if response.status_code == 403:
                permission = REQUIRED_PERMISSION.get(path, "a permission your account doesn't have")
                if permission in ADMIN_ONLY:
                    hint = f"This endpoint needs {permission}, an admin-only permission. Use mock mode for this report."
                else:
                    hint = (f"This endpoint needs {permission}, and your organization hasn't granted it "
                            "to Graph Explorer. That's normal for student accounts.")
                raise GraphError(f"Graph returned 403 Forbidden for {path}. {hint}", 403)
            if response.status_code == 429:
                raise GraphError(f"Graph kept rate limiting {path} after {MAX_RETRIES} retries. Try again later.", 429)
            if response.status_code == 400 and path.startswith("/me/authentication"):
                # Authentication-method endpoints only exist for work/school (Entra ID) accounts.
                raise GraphError(
                    f"Graph returned 400 Bad Request for {path}. This endpoint only works for work or school "
                    "(Entra ID) accounts. Personal Microsoft accounts (outlook.com, hotmail.com) don't support it, "
                    "so this is expected if you signed in to Graph Explorer with a personal account.",
                    400,
                )
            if not response.ok:
                detail = _graph_error_message(response)
                raise GraphError(f"Graph returned HTTP {response.status_code} for {path}.{detail}",
                                 response.status_code)
            return response.json()
        raise GraphError("unreachable")  # pragma: no cover

    def _get(self, path: str, params: dict | None = None) -> dict:
        """GET a single object, e.g. /me."""
        return self._request(self.base_url + path, path, params)

    def _get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """GET a collection and follow @odata.nextLink until every page is fetched."""
        records: list[dict] = []
        url, query = self.base_url + path, params
        while url:
            page = self._request(url, path, query)
            records.extend(page.get("value", []))
            url = page.get("@odata.nextLink")  # full URL to the next page, or None
            query = None  # the nextLink already contains the query string
        return records

    def _tenant_report(self, path: str, params: dict | None, fallback_method: Callable[[], list[dict]]):
        """Try a tenant-wide endpoint; if Graph refuses, explain why and use mock data."""
        try:
            return self._get_all(path, params)
        except GraphError as err:
            message = f"{err} Falling back to mock data for this report."
            self.messages.append(message)
            self.notify(message)
            return fallback_method()

    # -- DataSource interface ----------------------------------------------

    def get_users(self) -> list[dict]:
        return self._tenant_report("/users", {"$select": USER_FIELDS, "$top": "999"}, self.fallback.get_users)

    def get_registration_details(self) -> list[dict]:
        return self._tenant_report("/reports/authenticationMethods/userRegistrationDetails", None,
                                   self.fallback.get_registration_details)

    def get_sign_ins(self) -> list[dict]:
        return self._tenant_report("/auditLogs/signIns", {"$top": "1000"}, self.fallback.get_sign_ins)

    def get_me(self) -> dict:
        """GET /me: works with any signed-in account (User.Read)."""
        return self._get("/me")

    def get_my_auth_methods(self) -> list[dict]:
        """GET /me/authentication/methods: may be 403 if the org hasn't granted it."""
        return self._get_all("/me/authentication/methods")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_source(name: str | None = None) -> DataSource:
    """Return the source picked by DATA_SOURCE (or `name`). Defaults to mock."""
    name = (name or config.get_data_source()).lower()
    if name == "graph":
        token = config.get_graph_token()
        if not token:
            print("DATA_SOURCE=graph but GRAPH_TOKEN is empty. Using mock data.", file=sys.stderr)
            return MockSource()
        return GraphSource(token)
    return MockSource()
