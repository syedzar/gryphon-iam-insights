"""Small hand-written fixtures with known answers (not the big generated files)."""

from datetime import datetime, timezone

import pytest

D = "mock.uoguelph.example"
TODAY = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def reg(upn, methods, default, *, admin=False, mfa=True, passwordless=False):
    return {
        "id": f"id-{upn}",
        "userPrincipalName": f"{upn}@{D}",
        "userDisplayName": upn.title(),
        "isAdmin": admin,
        "isMfaRegistered": mfa,
        "isMfaCapable": mfa,
        "isPasswordlessCapable": passwordless,
        "methodsRegistered": methods,
        "defaultMfaMethod": default,
    }


@pytest.fixture
def reg_details():
    """8 users. Known answers:
    strongest: passkey 1, fido2 1, auth-passwordless 1, auth-push 2, otp 0, sms 1, email 1, none 1
    MFA registered: 6/8 = 75.0%   passwordless: 3/8 = 37.5%
    SMS list: smsadmin (admin, first), smsdefault, fidouser (SMS is its default)
    admins without strong MFA: smsadmin
    """
    return [
        reg("passkeyuser", ["passKeyDeviceBound", "microsoftAuthenticatorPush"], "microsoftAuthenticatorPush",
            passwordless=True),
        reg("fidouser", ["fido2", "mobilePhone"], "mobilePhone", passwordless=True),
        reg("phonesignin", ["microsoftAuthenticatorPasswordless", "microsoftAuthenticatorPush"],
            "microsoftAuthenticatorPush", passwordless=True),
        reg("pushadmin", ["microsoftAuthenticatorPush", "email"], "microsoftAuthenticatorPush", admin=True),
        reg("smsdefault", ["mobilePhone", "microsoftAuthenticatorPush"], "mobilePhone"),
        reg("smsadmin", ["mobilePhone"], "mobilePhone", admin=True),
        reg("emailonly", ["email"], "none", mfa=False),
        reg("nothing", [], "none", mfa=False),
    ]


def user(upn, employee_type="Student", *, enabled=True, leave=None):
    return {
        "id": f"id-{upn}",
        "displayName": upn.title(),
        "userPrincipalName": f"{upn}@{D}",
        "mail": f"{upn}@{D}",
        "accountEnabled": enabled,
        "employeeType": employee_type,
        "department": "School of Engineering",
        "createdDateTime": "2022-09-01T12:00:00Z",
        "employeeLeaveDateTime": leave,
        "signInActivity": {"lastSignInDateTime": None},
    }


@pytest.fixture
def users():
    """6 users. As of TODAY with a 30-day grace period, only grad45 and grad200 are stale."""
    return [
        user("alice"),
        user("bob", "Staff"),
        user("grad10", "Graduated", leave="2026-11-12T12:00:00Z"),            # 10 days: inside grace
        user("grad45", "Graduated", leave="2026-10-08T12:00:00Z"),            # 45 days: stale
        user("grad200", "Graduated", leave="2026-05-06T12:00:00Z"),           # 200 days: stale
        user("graddisabled", "Graduated", enabled=False, leave="2025-01-01T12:00:00Z"),  # already disabled
    ]


def sign_in(sid, upn, when, country="CA", city="Guelph", *, mfa=True, error=0):
    return {
        "id": sid,
        "createdDateTime": when,
        "userPrincipalName": f"{upn}@{D}",
        "appDisplayName": "Microsoft Teams",
        "ipAddress": "192.0.2.10",
        "clientAppUsed": "Browser",
        "isInteractive": True,
        "location": {"city": city, "state": None, "countryOrRegion": country},
        "status": {"errorCode": error, "failureReason": "Other."},
        "authenticationRequirement": "multiFactorAuthentication" if mfa else "singleFactorAuthentication",
        "conditionalAccessStatus": "success" if mfa and not error else "notApplied",
    }


def failures(prefix, upn, start_minute, count, step_seconds=60):
    """`count` wrong-password sign-ins starting at 10:<start_minute>, `step_seconds` apart."""
    out = []
    for i in range(count):
        total = start_minute * 60 + i * step_seconds
        out.append(sign_in(f"{prefix}{i}", upn, f"2026-11-20T10:{total // 60:02d}:{total % 60:02d}Z",
                           mfa=False, error=50126))
    return out


@pytest.fixture
def sign_ins():
    """Known answers for the default rules:
    foreign_single_factor: s-foreign (1)
    brute force: carol's 5 failures in 4 min (1); dave's 4 failures do not fire
    impossible travel: erin Guelph -> London 60 min apart (1); frank 5 h apart does not fire
    graduated active: grad45 success (1); grad45's failure does not count
    s-safe: Canadian MFA sign-in, no finding
    """
    return (
        [
            sign_in("s-safe", "alice", "2026-11-20T09:00:00Z"),
            sign_in("s-foreign", "bob", "2026-11-19T08:00:00Z", "NG", "Lagos", mfa=False),
            sign_in("s-foreign-mfa", "alice", "2026-11-10T08:00:00Z", "FR", "Paris"),  # MFA: fine
            sign_in("t1", "erin", "2026-11-18T12:00:00Z"),
            sign_in("t2", "erin", "2026-11-18T13:00:00Z", "GB", "London"),
            sign_in("f1", "frank", "2026-11-17T08:00:00Z"),
            sign_in("f2", "frank", "2026-11-17T13:00:00Z", "US", "Chicago"),
            sign_in("g1", "grad45", "2026-11-16T15:00:00Z"),
            sign_in("g2", "grad45", "2026-11-16T15:05:00Z", error=50126, mfa=False),
        ]
        + failures("c", "carol", 0, 5)    # 5 failures over 4 minutes -> fires
        + failures("d", "dave", 30, 4)    # 4 failures -> does not fire
    )


@pytest.fixture
def today():
    return TODAY
