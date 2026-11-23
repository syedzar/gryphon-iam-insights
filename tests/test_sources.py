"""Data source tests. requests is faked, so there are no real network calls."""

from unittest.mock import MagicMock

import pytest

from iam_insights import sources
from iam_insights.sources import GraphError, GraphSource, MockSource

# Required Graph keys for every mock record (section 5 of the README).
USER_KEYS = {"id", "displayName", "userPrincipalName", "mail", "accountEnabled", "employeeType",
             "department", "createdDateTime", "employeeLeaveDateTime", "signInActivity"}
REG_KEYS = {"id", "userPrincipalName", "userDisplayName", "isAdmin", "isMfaRegistered", "isMfaCapable",
            "isPasswordlessCapable", "methodsRegistered", "defaultMfaMethod"}
SIGNIN_KEYS = {"id", "createdDateTime", "userPrincipalName", "appDisplayName", "ipAddress", "clientAppUsed",
               "isInteractive", "location", "status", "authenticationRequirement", "conditionalAccessStatus"}
REAL_METHOD_NAMES = {"microsoftAuthenticatorPush", "microsoftAuthenticatorPasswordless", "passKeyDeviceBound",
                     "fido2", "softwareOneTimePasscode", "mobilePhone", "email"}


def fake_response(status=200, body=None, headers=None):
    response = MagicMock()
    response.status_code = status
    response.ok = 200 <= status < 300
    response.headers = headers or {}
    response.json.return_value = body or {}
    return response


def graph_with(*responses, fallback=None):
    """A GraphSource whose session returns the given responses in order."""
    session = MagicMock()
    session.headers = {}
    session.get.side_effect = list(responses)
    sleeps = []
    notes = []
    source = GraphSource("fake-token", session=session, fallback=fallback or MagicMock(),
                         sleep=sleeps.append, notify=notes.append)
    return source, session, sleeps, notes


# ---------------------------------------------------------------------------
# MockSource and the committed mock data
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock():
    return MockSource()


def test_mock_source_loads_every_file(mock):
    assert len(mock.get_users()) == 200
    assert len(mock.get_registration_details()) == 200
    assert 2900 <= len(mock.get_sign_ins()) <= 3100
    assert mock.get_me() == mock.get_users()[0]
    methods = mock.get_my_auth_methods()
    assert methods[0]["@odata.type"] == "#microsoft.graph.passwordAuthenticationMethod"


def test_shape_users(mock):
    for u in mock.get_users():
        assert USER_KEYS <= set(u), u["id"]
        assert u["userPrincipalName"].endswith("@mock.uoguelph.example")
        assert u["employeeType"] in {"Student", "Staff", "Faculty", "Graduated"}
        assert "lastSignInDateTime" in u["signInActivity"]


def test_shape_registration_details(mock):
    user_ids = {u["id"] for u in mock.get_users()}
    for r in mock.get_registration_details():
        assert REG_KEYS <= set(r)
        assert r["id"] in user_ids
        assert set(r["methodsRegistered"]) <= REAL_METHOD_NAMES


def test_shape_sign_ins(mock):
    for s in mock.get_sign_ins():
        assert SIGNIN_KEYS <= set(s)
        assert {"city", "state", "countryOrRegion"} <= set(s["location"])
        assert {"errorCode", "failureReason"} <= set(s["status"])
        assert s["ipAddress"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_mock_files_are_wrapped_like_graph():
    import json
    from iam_insights.config import MOCK_DIR
    for name in ("users.json", "userRegistrationDetails.json", "signIns.json"):
        payload = json.loads((MOCK_DIR / name).read_text(encoding="utf-8"))
        assert payload["@odata.context"].startswith("https://graph.microsoft.com/v1.0/$metadata#")
        assert isinstance(payload["value"], list)


# ---------------------------------------------------------------------------
# GraphSource
# ---------------------------------------------------------------------------

def test_graph_sends_bearer_token():
    source, session, _, _ = graph_with(fake_response(body={"id": "me"}))
    assert source.get_me() == {"id": "me"}
    assert session.headers["Authorization"] == "Bearer fake-token"
    assert session.get.call_args.args[0] == "https://graph.microsoft.com/v1.0/me"


def test_graph_follows_next_link_across_two_pages():
    page1 = fake_response(body={"value": [{"id": "1"}, {"id": "2"}],
                                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"})
    page2 = fake_response(body={"value": [{"id": "3"}]})
    source, session, _, _ = graph_with(page1, page2)

    assert [u["id"] for u in source.get_users()] == ["1", "2", "3"]
    assert session.get.call_count == 2
    assert session.get.call_args_list[1].args[0].endswith("$skiptoken=abc")
    assert session.get.call_args_list[1].kwargs["params"] is None  # nextLink already has the query


def test_graph_retries_on_429_using_retry_after():
    source, session, sleeps, _ = graph_with(
        fake_response(429, headers={"Retry-After": "7"}),
        fake_response(429, headers={"Retry-After": "3"}),
        fake_response(body={"id": "me"}),
    )
    assert source.get_me() == {"id": "me"}
    assert sleeps == [7.0, 3.0]
    assert session.get.call_count == 3


def test_graph_gives_up_after_three_retries():
    source, session, sleeps, _ = graph_with(*[fake_response(429, headers={"Retry-After": "1"})] * 4)
    with pytest.raises(GraphError, match="rate limiting"):
        source.get_me()
    assert len(sleeps) == 3
    assert session.get.call_count == 4


def test_graph_403_becomes_friendly_error():
    source, _, _, _ = graph_with(fake_response(403))
    with pytest.raises(GraphError) as err:
        source.get_my_auth_methods()
    assert err.value.status_code == 403
    assert "UserAuthenticationMethod.Read" in str(err.value)


def test_graph_401_explains_expired_token():
    source, _, _, _ = graph_with(fake_response(401))
    with pytest.raises(GraphError, match="expired"):
        source.get_me()


def test_graph_other_http_error():
    source, _, _, _ = graph_with(fake_response(500))
    with pytest.raises(GraphError, match="HTTP 500"):
        source.get_me()


def test_graph_error_includes_graphs_own_message():
    body = {"error": {"code": "Request_ResourceNotFound", "message": "Resource does not exist."}}
    source, _, _, _ = graph_with(fake_response(404, body=body))
    with pytest.raises(GraphError, match=r"HTTP 404 for /me\. \(Request_ResourceNotFound: Resource does not exist\.\)"):
        source.get_me()


def test_graph_400_on_auth_methods_explains_personal_accounts():
    source, _, _, _ = graph_with(fake_response(400))
    with pytest.raises(GraphError) as err:
        source.get_my_auth_methods()
    assert err.value.status_code == 400
    assert "Personal Microsoft accounts" in str(err.value)


def test_tenant_report_403_falls_back_to_mock_with_message():
    fallback = MagicMock()
    fallback.get_sign_ins.return_value = [{"id": "mock-sign-in"}]
    source, _, _, notes = graph_with(fake_response(403), fallback=fallback)

    assert source.get_sign_ins() == [{"id": "mock-sign-in"}]  # no crash
    assert "AuditLog.Read.All, an admin-only permission. Use mock mode for this report." in notes[0]
    assert source.messages == notes


def test_registration_details_fall_back_too():
    fallback = MagicMock()
    fallback.get_registration_details.return_value = []
    source, _, _, notes = graph_with(fake_response(403), fallback=fallback)
    assert source.get_registration_details() == []
    assert len(notes) == 1


def test_graph_source_needs_a_token():
    with pytest.raises(GraphError, match="GRAPH_TOKEN"):
        GraphSource("")


def test_get_source_defaults_to_mock(monkeypatch):
    monkeypatch.delenv("DATA_SOURCE", raising=False)
    assert sources.get_source().name == "mock"


def test_get_source_graph_without_token_uses_mock(monkeypatch):
    monkeypatch.setenv("DATA_SOURCE", "graph")
    monkeypatch.setenv("GRAPH_TOKEN", "")
    assert sources.get_source().name == "mock"


def test_get_source_graph_with_token(monkeypatch):
    monkeypatch.setenv("DATA_SOURCE", "graph")
    monkeypatch.setenv("GRAPH_TOKEN", "abc")
    assert sources.get_source().name == "graph"
