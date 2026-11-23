"""Generate synthetic IAM data in Microsoft Graph's real JSON shape.

Run:  python -m iam_insights.generate_mock --users 200 --seed 42

Writes three files to data/mock/, each wrapped the way Graph wraps a response:
    {"@odata.context": "...", "value": [ ... ]}

Everything is driven by one random seed and one fixed reference date, so the
same command always produces byte-for-byte the same files.

A few "interesting" cases are planted on purpose so the reports have something
to find (foreign single-factor sign-ins, brute force bursts, one impossible
travel case, and sign-ins by graduates whose accounts are still enabled).
"""

import argparse
import json
import random
import re
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

from iam_insights.config import MOCK_DIR

DOMAIN = "mock.uoguelph.example"  # .example is reserved, so no real address exists
GRAPH = "https://graph.microsoft.com/v1.0/$metadata#"
DEFAULT_TODAY = "2026-11-22"  # fixed "now" so the data never changes between runs

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

ACADEMIC_DEPARTMENTS = [
    "School of Engineering",
    "School of Computer Science",
    "Department of Mathematics and Statistics",
    "Department of Physics",
    "Department of Chemistry",
    "Department of Psychology",
    "College of Business",
    "School of Environmental Sciences",
    "Department of Molecular and Cellular Biology",
    "School of English and Theatre Studies",
]
STAFF_DEPARTMENTS = [
    "IT Services",
    "Library",
    "Student Housing",
    "Registrar's Office",
    "Human Resources",
    "Finance",
    "Facilities",
]

# Canadian locations used for "normal" sign-ins. Guelph is weighted heavily.
CANADIAN_LOCATIONS = [
    ({"city": "Guelph", "state": "Ontario", "countryOrRegion": "CA"}, 60),
    ({"city": "Toronto", "state": "Ontario", "countryOrRegion": "CA"}, 12),
    ({"city": "Kitchener", "state": "Ontario", "countryOrRegion": "CA"}, 8),
    ({"city": "Waterloo", "state": "Ontario", "countryOrRegion": "CA"}, 6),
    ({"city": "Hamilton", "state": "Ontario", "countryOrRegion": "CA"}, 6),
    ({"city": "Ottawa", "state": "Ontario", "countryOrRegion": "CA"}, 4),
    ({"city": "Vancouver", "state": "British Columbia", "countryOrRegion": "CA"}, 2),
    ({"city": "Montreal", "state": "Quebec", "countryOrRegion": "CA"}, 2),
]
GUELPH = CANADIAN_LOCATIONS[0][0]

FOREIGN_LOCATIONS = [
    {"city": "Lagos", "state": "Lagos", "countryOrRegion": "NG"},
    {"city": "Moscow", "state": "Moscow", "countryOrRegion": "RU"},
    {"city": "Sao Paulo", "state": "Sao Paulo", "countryOrRegion": "BR"},
    {"city": "Shenzhen", "state": "Guangdong", "countryOrRegion": "CN"},
    {"city": "Mumbai", "state": "Maharashtra", "countryOrRegion": "IN"},
    {"city": "Berlin", "state": "Berlin", "countryOrRegion": "DE"},
    {"city": "Hanoi", "state": "Hanoi", "countryOrRegion": "VN"},
    {"city": "Bucharest", "state": "Bucharest", "countryOrRegion": "RO"},
    {"city": "Chicago", "state": "Illinois", "countryOrRegion": "US"},
    {"city": "Paris", "state": "Ile-de-France", "countryOrRegion": "FR"},
]
LONDON = {"city": "London", "state": "England", "countryOrRegion": "GB"}

APPS = [
    ("Office 365 Exchange Online", 30),
    ("Microsoft Teams", 25),
    ("Office 365 SharePoint Online", 15),
    ("OneDrive SyncEngine", 10),
    ("Learning Management System (mock)", 15),
    ("Student Information System (mock)", 5),
]
CLIENT_APPS = [("Browser", 60), ("Mobile Apps and Desktop clients", 40)]

# Documentation-only IP ranges (RFC 5737). They never route on the internet.
IP_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]

WRONG_PASSWORD = 50126
WRONG_PASSWORD_REASON = "Error validating credentials due to invalid username or password."


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def iso(dt: datetime) -> str:
    """Format a datetime the way Graph does: 2026-11-20T09:15:00Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def weighted(rng: random.Random, options):
    """Pick one item from a list of (item, weight) pairs."""
    items = [item for item, _ in options]
    weights = [w for _, w in options]
    return rng.choices(items, weights=weights, k=1)[0]


def new_id(rng: random.Random) -> str:
    """A UUID that comes from our seeded random generator (so it's repeatable)."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def ascii_letters(text: str) -> str:
    """'Zoë O'Brien' -> 'zoeobrien' (safe for an email address)."""
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z]", "", plain.lower())


def random_ip(rng: random.Random) -> str:
    return rng.choice(IP_PREFIXES) + str(rng.randint(1, 254))


def split_counts(total: int, shares: dict[str, float]) -> dict[str, int]:
    """Turn percentages into whole counts that add up exactly to `total`."""
    counts = {key: int(total * share) for key, share in shares.items()}
    # Hand out any leftover from rounding down, biggest share first.
    leftover = total - sum(counts.values())
    for key in sorted(shares, key=shares.get, reverse=True)[:leftover]:
        counts[key] += 1
    return counts


# ---------------------------------------------------------------------------
# users.json
# ---------------------------------------------------------------------------

def make_users(n: int, rng: random.Random, fake: Faker, today: datetime) -> list[dict]:
    """Build n users. ~70% Student, 12% Staff, 8% Faculty, 10% Graduated."""
    counts = split_counts(n, {"Student": 0.70, "Staff": 0.12, "Faculty": 0.08, "Graduated": 0.10})
    types = [t for t, c in counts.items() for _ in range(c)]
    rng.shuffle(types)

    # Graduate plan: ~60% still enabled. Of the enabled ones, about a third
    # graduated recently (inside the 30-day grace period), the rest longer ago.
    n_grads = counts["Graduated"]
    n_grads_enabled = round(n_grads * 0.6)
    n_recent = max(1, round(n_grads_enabled / 3)) if n_grads_enabled else 0
    grad_plan = []  # list of (accountEnabled, days_since_graduation)
    for i in range(n_grads):
        if i < n_recent:
            grad_plan.append((True, rng.randint(5, 25)))           # inside grace period
        elif i < n_recent + 2 and i < n_grads_enabled:
            grad_plan.append((True, rng.randint(45, 110)))         # just past grace
        elif i < n_grads_enabled:
            grad_plan.append((True, rng.randint(125, 400)))        # long ago
        else:
            grad_plan.append((False, rng.randint(30, 400)))        # already cleaned up
    rng.shuffle(grad_plan)

    users, used_upns = [], set()
    for employee_type in types:
        first, last = fake.first_name(), fake.last_name()
        # UPN like jlee042: first initial + last name + 3 digits, unique.
        while True:
            upn_local = f"{ascii_letters(first)[:1]}{ascii_letters(last)[:8]}{rng.randint(1, 999):03d}"
            if upn_local not in used_upns:
                used_upns.add(upn_local)
                break
        upn = f"{upn_local}@{DOMAIN}"

        if employee_type in ("Student", "Graduated"):
            department = rng.choice(ACADEMIC_DEPARTMENTS)
            start_year = rng.randint(2021, 2026)
            created = datetime(start_year, 9, 1, 12, 0, tzinfo=timezone.utc)
        elif employee_type == "Faculty":
            department = rng.choice(ACADEMIC_DEPARTMENTS)
            created = datetime(rng.randint(2015, 2025), rng.randint(1, 12), 1, 12, 0, tzinfo=timezone.utc)
        else:  # Staff
            department = rng.choice(STAFF_DEPARTMENTS)
            created = datetime(rng.randint(2015, 2025), rng.randint(1, 12), 1, 12, 0, tzinfo=timezone.utc)

        enabled, leave = True, None
        if employee_type == "Graduated":
            enabled, days_ago = grad_plan.pop()
            leave = today - timedelta(days=days_ago)
            # A graduate's account can't be newer than ~3.5 years before leaving.
            created = min(created, leave - timedelta(days=365 * 3))

        users.append({
            "id": new_id(rng),
            "displayName": f"{first} {last}",
            "userPrincipalName": upn,
            "mail": upn,
            "accountEnabled": enabled,
            "employeeType": employee_type,
            "department": department,
            "createdDateTime": iso(created),
            "employeeLeaveDateTime": iso(leave) if leave else None,
            "signInActivity": {"lastSignInDateTime": None},  # filled in after sign-ins exist
        })
    return users


# ---------------------------------------------------------------------------
# userRegistrationDetails.json
# ---------------------------------------------------------------------------

def make_registration_details(users: list[dict], rng: random.Random, today: datetime) -> list[dict]:
    """One registration record per user.

    Mix: 55% Authenticator, 15% passkey/FIDO2, 20% SMS default, 5% software OTP, 5% none.
    """
    n = len(users)
    counts = split_counts(n, {"authenticator": 0.55, "passkey": 0.15, "sms": 0.20, "otp": 0.05, "none": 0.05})

    # Choose 3 admins from Staff/Faculty and give them fixed profiles, so the
    # "admins" reports always have a predictable story:
    #   admin 1: passkey (good), admin 2: SMS default (bad), admin 3: software OTP (bad).
    staff_like = [i for i, u in enumerate(users) if u["employeeType"] in ("Staff", "Faculty")]
    admin_profiles = ["passkey", "sms", "otp"]
    admin_idx = rng.sample(staff_like, k=min(3, len(staff_like)))
    profiles = {idx: admin_profiles[k] for k, idx in enumerate(admin_idx)}
    for profile in profiles.values():
        counts[profile] -= 1

    # Everyone else gets a shuffled profile from the remaining counts.
    pool = [p for p, c in counts.items() for _ in range(max(c, 0))]
    rng.shuffle(pool)
    for i in range(n):
        if i not in profiles:
            profiles[i] = pool.pop()

    details = []
    for i, user in enumerate(users):
        profile = profiles[i]
        passwordless = False
        if profile == "authenticator":
            methods = ["microsoftAuthenticatorPush"]
            if rng.random() < 0.10:  # a few use phone sign-in (passwordless Authenticator)
                methods.append("microsoftAuthenticatorPasswordless")
                passwordless = True
            if rng.random() < 0.5:
                methods.append("mobilePhone")  # backup phone is common
            if rng.random() < 0.3:
                methods.append("email")        # email is for password reset only
            default = "microsoftAuthenticatorPush"
        elif profile == "passkey":
            methods = [rng.choice(["passKeyDeviceBound", "fido2"]), "microsoftAuthenticatorPush"]
            passwordless = True
            default = "microsoftAuthenticatorPush"  # passkeys aren't a "default MFA method" in Graph
        elif profile == "sms":
            methods = ["mobilePhone"]
            extra = rng.random()
            if extra < 0.25:
                methods.append("microsoftAuthenticatorPush")  # has the app, but SMS is still default
            elif extra < 0.55:
                methods.append("email")
            default = "mobilePhone"
        elif profile == "otp":
            methods = ["softwareOneTimePasscode"]
            if rng.random() < 0.5:
                methods.append("mobilePhone")
            default = "softwareOneTimePasscode"
        else:  # none
            methods = ["email"] if rng.random() < 0.5 else []
            default = "none"

        mfa = profile != "none"
        details.append({
            "id": user["id"],
            "userPrincipalName": user["userPrincipalName"],
            "userDisplayName": user["displayName"],
            "userType": "member",
            "isAdmin": i in admin_idx,
            "isSsprRegistered": bool(methods),
            "isMfaRegistered": mfa,
            "isMfaCapable": mfa and user["accountEnabled"],
            "isPasswordlessCapable": passwordless,
            "methodsRegistered": methods,
            "defaultMfaMethod": default,
            "lastUpdatedDateTime": iso(today - timedelta(days=rng.randint(1, 20))),
        })
    return details


# ---------------------------------------------------------------------------
# signIns.json
# ---------------------------------------------------------------------------

def sign_in(rng, user, when, location, *, mfa=True, error=0, app=None, client=None) -> dict:
    """Build one sign-in record in Graph's /auditLogs/signIns shape."""
    success = error == 0
    return {
        "id": new_id(rng),
        "createdDateTime": iso(when),
        "userId": user["id"],
        "userDisplayName": user["displayName"],
        "userPrincipalName": user["userPrincipalName"],
        "appDisplayName": app or weighted(rng, APPS),
        "ipAddress": random_ip(rng),
        "clientAppUsed": client or weighted(rng, CLIENT_APPS),
        "isInteractive": True,
        "location": dict(location),
        "status": {
            "errorCode": error,
            "failureReason": "Other." if success else WRONG_PASSWORD_REASON,
        },
        "authenticationRequirement": "multiFactorAuthentication" if mfa else "singleFactorAuthentication",
        # Conditional access is only evaluated after the password step succeeds.
        "conditionalAccessStatus": "success" if (success and mfa) else "notApplied",
    }


def random_time(rng: random.Random, today: datetime, days: int = 30) -> datetime:
    """A random moment in the last `days` days, between 11:00 and 23:59 UTC (daytime in Ontario)."""
    day = today - timedelta(days=rng.randint(1, days))
    return day.replace(hour=rng.randint(11, 23), minute=rng.randint(0, 59), second=rng.randint(0, 59))


def make_sign_ins(users, rng, today, target=3000) -> list[dict]:
    """About `target` sign-ins over the last 30 days, with planted cases."""
    active = [u for u in users if u["accountEnabled"] and u["employeeType"] != "Graduated"]
    enabled_grads = [u for u in users if u["accountEnabled"] and u["employeeType"] == "Graduated"]

    # Pick the users for each planted case up front so they don't overlap.
    picks = rng.sample(active, k=min(len(active), 12 + 3 + 1 + 6))
    foreign_sf_users = picks[:12]      # foreign single-factor sign-ins
    brute_users = picks[12:15]         # brute force victims
    travel_user = picks[15]            # impossible travel
    exchange_users = picks[16:22]      # studying abroad: all sign-ins from one country, with MFA

    planted, normal = [], []
    # "Protected" sign-ins: other sign-ins by the same user near these
    # (but in another country) are removed, so only the planted case shows up.
    protected: list[tuple[dict, datetime]] = []

    # 1) Foreign sign-ins with single-factor authentication (12, one per user).
    for k, user in enumerate(foreign_sf_users):
        when = random_time(rng, today)
        loc = FOREIGN_LOCATIONS[k % len(FOREIGN_LOCATIONS)]
        planted.append(sign_in(rng, user, when, loc, mfa=False, client="Mobile Apps and Desktop clients"))
        protected.append((user, when))

    # 2) Brute force: 6-8 wrong-password attempts within 10 minutes, from Canada.
    for user in brute_users:
        start = random_time(rng, today)
        for attempt in range(rng.randint(6, 8)):
            when = start + timedelta(seconds=attempt * rng.randint(40, 75))
            planted.append(sign_in(rng, user, when, GUELPH, mfa=False, error=WRONG_PASSWORD,
                                   app="Office 365 Exchange Online", client="Browser"))

    # 3) Impossible travel: Guelph, then London 75 minutes later (both with MFA).
    t0 = random_time(rng, today)
    planted.append(sign_in(rng, travel_user, t0, GUELPH))
    planted.append(sign_in(rng, travel_user, t0 + timedelta(minutes=75), LONDON))
    protected.append((travel_user, t0))

    # 4) Sign-ins by graduates whose accounts are still enabled (a few, successful).
    for user in enabled_grads[:3]:
        for _ in range(rng.randint(1, 2)):
            planted.append(sign_in(rng, user, random_time(rng, today), GUELPH))

    # Exchange students: every sign-in is from Paris with MFA. Safe, not flagged.
    exchange_ids = {u["id"] for u in exchange_users}
    paris = {"city": "Paris", "state": "Ile-de-France", "countryOrRegion": "FR"}

    # Normal background traffic, mostly successful MFA from Canada.
    for _ in range(target - len(planted)):
        user = rng.choice(active)
        when = random_time(rng, today)
        if user["id"] in exchange_ids:
            normal.append(sign_in(rng, user, when, paris))
            continue
        roll = rng.random()
        error = WRONG_PASSWORD if roll < 0.02 else 0                  # the odd typo
        mfa = not (0.02 <= roll < 0.10)                               # some single-factor (allowed in Canada)
        normal.append(sign_in(rng, user, when, weighted(rng, CANADIAN_LOCATIONS), mfa=mfa, error=error))

    # Remove background sign-ins that would accidentally create extra
    # "impossible travel" around a planted foreign sign-in.
    def too_close(s):
        for user, when in protected:
            created = datetime.fromisoformat(s["createdDateTime"].replace("Z", "+00:00"))
            if s["userId"] == user["id"] and abs(created - when) < timedelta(hours=3):
                return True
        return False

    normal = [s for s in normal if not too_close(s)]

    all_sign_ins = planted + normal
    # Newest first, like the Graph API returns them.
    all_sign_ins.sort(key=lambda s: s["createdDateTime"], reverse=True)
    return all_sign_ins


def fill_last_sign_in(users, sign_ins, rng, today):
    """Set signInActivity.lastSignInDateTime from the generated sign-ins."""
    latest = {}
    for s in sign_ins:
        if s["status"]["errorCode"] == 0:
            upn = s["userPrincipalName"]
            latest[upn] = max(latest.get(upn, ""), s["createdDateTime"])
    for u in users:
        if u["userPrincipalName"] in latest:
            u["signInActivity"]["lastSignInDateTime"] = latest[u["userPrincipalName"]]
        elif u["employeeLeaveDateTime"]:
            # Graduates who stopped signing in: last seen around graduation.
            leave = datetime.fromisoformat(u["employeeLeaveDateTime"].replace("Z", "+00:00"))
            u["signInActivity"]["lastSignInDateTime"] = iso(leave - timedelta(days=rng.randint(0, 10)))
        else:
            # Active but quiet in the last 30 days.
            u["signInActivity"]["lastSignInDateTime"] = iso(today - timedelta(days=rng.randint(31, 90)))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate(n_users: int = 200, seed: int = 42, today: str = DEFAULT_TODAY, sign_in_target: int = 3000):
    """Return (users, registration_details, sign_ins) as plain lists of dicts."""
    rng = random.Random(seed)
    fake = Faker("en_CA")
    fake.seed_instance(seed)
    now = datetime.fromisoformat(today).replace(hour=12, tzinfo=timezone.utc)

    users = make_users(n_users, rng, fake, now)
    details = make_registration_details(users, rng, now)
    sign_ins = make_sign_ins(users, rng, now, target=sign_in_target)
    fill_last_sign_in(users, sign_ins, rng, now)
    return users, details, sign_ins


def write_graph_file(path: Path, context: str, records: list[dict]):
    """Write records wrapped like a Graph response."""
    payload = {"@odata.context": GRAPH + context, "value": records}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate synthetic Graph-format IAM data.")
    parser.add_argument("--users", type=int, default=200, help="number of users (default 200)")
    parser.add_argument("--seed", type=int, default=42, help="random seed (default 42)")
    parser.add_argument("--today", default=DEFAULT_TODAY, help=f"reference date YYYY-MM-DD (default {DEFAULT_TODAY})")
    parser.add_argument("--out", type=Path, default=MOCK_DIR, help="output folder (default data/mock)")
    args = parser.parse_args(argv)

    if args.users < 30:
        parser.error("--users must be at least 30 so every planted case fits")

    users, details, sign_ins = generate(args.users, args.seed, args.today)
    args.out.mkdir(parents=True, exist_ok=True)
    write_graph_file(args.out / "users.json", "users", users)
    write_graph_file(args.out / "userRegistrationDetails.json",
                     "reports/authenticationMethods/userRegistrationDetails", details)
    write_graph_file(args.out / "signIns.json", "auditLogs/signIns", sign_ins)
    print(f"Wrote {len(users)} users, {len(details)} registration records, "
          f"{len(sign_ins)} sign-ins to {args.out}")


if __name__ == "__main__":
    main()
