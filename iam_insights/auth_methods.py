"""Features 1 and 2: authentication methods breakdown and the SMS migration list.

Input: records shaped like GET /reports/authenticationMethods/userRegistrationDetails.
"""

# Strongest first. Each label groups one or more Graph method names.
STRENGTH_ORDER = [
    ("Passkey / FIDO2", {"passKeyDeviceBound", "fido2", "passKeyDeviceBoundAuthenticator",
                         "passKeyDeviceBoundWindowsHello", "windowsHelloForBusiness"}),
    ("Authenticator passwordless", {"microsoftAuthenticatorPasswordless"}),
    ("Authenticator push", {"microsoftAuthenticatorPush"}),
    ("Software OTP", {"softwareOneTimePasscode", "hardwareOneTimePasscode"}),
    ("SMS / voice", {"mobilePhone", "alternateMobilePhone", "officePhone"}),
    ("Email", {"email"}),
]
NONE_LABEL = "None"
METHOD_LABELS = [label for label, _ in STRENGTH_ORDER] + [NONE_LABEL]

SMS_METHODS = STRENGTH_ORDER[4][1]
# "Strong" for admins = passkey, FIDO2, or Microsoft Authenticator (the top 3 groups).
STRONG_METHODS = set().union(*(names for _, names in STRENGTH_ORDER[:3]))


def strongest_method(record: dict) -> str:
    """Return the label of the strongest method this user has registered."""
    registered = set(record.get("methodsRegistered") or [])
    for label, names in STRENGTH_ORDER:
        if registered & names:
            return label
    return NONE_LABEL


def method_breakdown(reg_details: list[dict]) -> dict[str, int]:
    """Count users by their strongest registered method, strongest first.

    Every label appears in the result (with 0 if nobody has it), in strength order.
    """
    counts = {label: 0 for label in METHOD_LABELS}
    for record in reg_details:
        counts[strongest_method(record)] += 1
    return counts


def _percent(part: int, whole: int) -> float:
    """Percentage rounded to 1 decimal place. 0 users -> 0.0 instead of dividing by zero."""
    return round(100.0 * part / whole, 1) if whole else 0.0


def mfa_coverage(reg_details: list[dict]) -> float:
    """% of users with isMfaRegistered."""
    return _percent(sum(1 for r in reg_details if r.get("isMfaRegistered")), len(reg_details))


def passwordless_rate(reg_details: list[dict]) -> float:
    """% of users with isPasswordlessCapable."""
    return _percent(sum(1 for r in reg_details if r.get("isPasswordlessCapable")), len(reg_details))


def sms_migration_list(reg_details: list[dict]) -> list[dict]:
    """Users whose default MFA method is SMS/voice, or whose only methods are SMS/voice.

    Admins come first because a phished admin does the most damage.
    """
    result = []
    for r in reg_details:
        methods = set(r.get("methodsRegistered") or [])
        sms_default = r.get("defaultMfaMethod") in SMS_METHODS
        sms_only = bool(methods) and methods <= SMS_METHODS
        if sms_default or sms_only:
            result.append({
                "userPrincipalName": r["userPrincipalName"],
                "userDisplayName": r.get("userDisplayName"),
                "isAdmin": bool(r.get("isAdmin")),
                "defaultMfaMethod": r.get("defaultMfaMethod"),
                "methodsRegistered": sorted(methods),
                "reason": "SMS/voice is the only method" if sms_only else "SMS/voice is the default method",
            })
    # not isAdmin puts admins (False) before everyone else (True); then alphabetical.
    result.sort(key=lambda row: (not row["isAdmin"], row["userPrincipalName"]))
    return result


def admins_without_strong_mfa(reg_details: list[dict]) -> list[dict]:
    """Admins who have no passkey, FIDO2 key, or Microsoft Authenticator registered."""
    result = []
    for r in reg_details:
        if r.get("isAdmin") and not (set(r.get("methodsRegistered") or []) & STRONG_METHODS):
            result.append({
                "userPrincipalName": r["userPrincipalName"],
                "userDisplayName": r.get("userDisplayName"),
                "strongestMethod": strongest_method(r),
                "methodsRegistered": sorted(r.get("methodsRegistered") or []),
            })
    return sorted(result, key=lambda row: row["userPrincipalName"])
