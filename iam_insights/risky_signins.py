"""Feature 3: flag sign-ins that a conditional access policy would challenge or block.

Input: users (GET /users) and sign-ins (GET /auditLogs/signIns).
Every rule returns a list of findings with the same keys:
    {rule, userPrincipalName, signInId, createdDateTime, detail, severity}
"""

from collections import defaultdict
from datetime import datetime, timedelta

HOME_COUNTRY = "CA"
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def parse_time(value: str) -> datetime:
    """Parse Graph's '2026-11-20T09:15:00Z' format into a timezone-aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _country(sign_in: dict) -> str | None:
    return (sign_in.get("location") or {}).get("countryOrRegion")


def _place(sign_in: dict) -> str:
    loc = sign_in.get("location") or {}
    return f"{loc.get('city') or '?'}, {loc.get('countryOrRegion') or '?'}"


def _finding(rule: str, sign_in: dict, detail: str, severity: str) -> dict:
    return {
        "rule": rule,
        "userPrincipalName": sign_in["userPrincipalName"],
        "signInId": sign_in["id"],
        "createdDateTime": sign_in["createdDateTime"],
        "detail": detail,
        "severity": severity,
    }


def _by_user(sign_ins: list[dict]) -> dict[str, list[dict]]:
    """Group sign-ins by user, each list sorted oldest first."""
    groups = defaultdict(list)
    for s in sign_ins:
        groups[s["userPrincipalName"]].append(s)
    for items in groups.values():
        items.sort(key=lambda s: parse_time(s["createdDateTime"]))
    return groups


def rule_foreign_single_factor(sign_ins: list[dict], home_country: str = HOME_COUNTRY) -> list[dict]:
    """Policy mimicked: "Require MFA for sign-ins from outside Canada"."""
    findings = []
    for s in sign_ins:
        country = _country(s)
        if country and country != home_country and s.get("authenticationRequirement") == "singleFactorAuthentication":
            findings.append(_finding(
                "foreign_single_factor", s,
                f"Single-factor sign-in from {_place(s)} to {s.get('appDisplayName')}", "high"))
    return findings


def rule_password_spray_or_brute_force(sign_ins: list[dict], threshold: int = 5,
                                       window_minutes: int = 10) -> list[dict]:
    """`threshold` or more failed sign-ins for one user within `window_minutes`.

    One finding per burst: once a burst is reported, we skip past it so the
    same attack isn't reported several times.
    """
    window = timedelta(minutes=window_minutes)
    failures = [s for s in sign_ins if (s.get("status") or {}).get("errorCode", 0) != 0]
    findings = []
    for upn, items in _by_user(failures).items():
        times = [parse_time(s["createdDateTime"]) for s in items]
        start = 0
        while start < len(items):
            # Find the last failure that is still inside the window starting at `start`.
            end = start
            while end + 1 < len(items) and times[end + 1] - times[start] <= window:
                end += 1
            count = end - start + 1
            if count >= threshold:
                minutes = (times[end] - times[start]).total_seconds() / 60
                findings.append(_finding(
                    "password_spray_or_brute_force", items[end],
                    f"{count} failed sign-ins in {minutes:.0f} min (threshold {threshold} in {window_minutes} min)",
                    "high"))
                start = end + 1  # skip past this burst
            else:
                start += 1
    return findings


def rule_impossible_travel(sign_ins: list[dict], max_hours: float = 2.0) -> list[dict]:
    """The same user in 2 different countries less than `max_hours` apart."""
    limit = timedelta(hours=max_hours)
    findings = []
    for upn, items in _by_user(sign_ins).items():
        for previous, current in zip(items, items[1:]):
            c1, c2 = _country(previous), _country(current)
            gap = parse_time(current["createdDateTime"]) - parse_time(previous["createdDateTime"])
            if c1 and c2 and c1 != c2 and gap < limit:
                findings.append(_finding(
                    "impossible_travel", current,
                    f"{_place(previous)} then {_place(current)} {gap.total_seconds() / 60:.0f} min apart",
                    "medium"))
    return findings


def rule_graduated_account_active(users: list[dict], sign_ins: list[dict]) -> list[dict]:
    """A successful sign-in by a user whose employeeType is "Graduated"."""
    graduates = {u["userPrincipalName"] for u in users if u.get("employeeType") == "Graduated"}
    findings = []
    for s in sign_ins:
        if s["userPrincipalName"] in graduates and (s.get("status") or {}).get("errorCode", 0) == 0:
            findings.append(_finding(
                "graduated_account_active", s,
                f"Graduated user signed in to {s.get('appDisplayName')} from {_place(s)}", "medium"))
    return findings


def run_all_rules(users: list[dict], sign_ins: list[dict]) -> list[dict]:
    """Run every rule. Sorted by severity (high first), then newest first."""
    findings = (
        rule_foreign_single_factor(sign_ins)
        + rule_password_spray_or_brute_force(sign_ins)
        + rule_impossible_travel(sign_ins)
        + rule_graduated_account_active(users, sign_ins)
    )
    # Sort newest first, then stable-sort by severity so time order is kept inside each level.
    findings.sort(key=lambda f: f["createdDateTime"], reverse=True)
    findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
    return findings
