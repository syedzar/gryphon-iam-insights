from iam_insights import auth_methods as am


def test_strongest_method_ordering():
    assert am.strongest_method({"methodsRegistered": ["mobilePhone", "fido2", "microsoftAuthenticatorPush"]}) \
        == "Passkey / FIDO2"
    assert am.strongest_method({"methodsRegistered": ["microsoftAuthenticatorPush",
                                                      "microsoftAuthenticatorPasswordless"]}) \
        == "Authenticator passwordless"
    assert am.strongest_method({"methodsRegistered": ["mobilePhone", "softwareOneTimePasscode"]}) == "Software OTP"
    assert am.strongest_method({"methodsRegistered": ["email", "mobilePhone"]}) == "SMS / voice"
    assert am.strongest_method({"methodsRegistered": ["email"]}) == "Email"
    assert am.strongest_method({"methodsRegistered": []}) == "None"
    assert am.strongest_method({}) == "None"


def test_method_labels_are_in_strength_order():
    assert am.METHOD_LABELS == ["Passkey / FIDO2", "Authenticator passwordless", "Authenticator push",
                                "Software OTP", "SMS / voice", "Email", "None"]


def test_method_breakdown(reg_details):
    result = am.method_breakdown(reg_details)
    assert list(result) == am.METHOD_LABELS  # every label, strongest first
    assert result == {"Passkey / FIDO2": 2, "Authenticator passwordless": 1, "Authenticator push": 2,
                      "Software OTP": 0, "SMS / voice": 1, "Email": 1, "None": 1}
    assert sum(result.values()) == len(reg_details)


def test_mfa_coverage(reg_details):
    assert am.mfa_coverage(reg_details) == 75.0


def test_passwordless_rate(reg_details):
    assert am.passwordless_rate(reg_details) == 37.5


def test_percentages_with_no_users():
    assert am.mfa_coverage([]) == 0.0
    assert am.passwordless_rate([]) == 0.0


def test_sms_list_catches_sms_default_and_puts_admin_first(reg_details):
    result = am.sms_migration_list(reg_details)
    upns = [row["userPrincipalName"].split("@")[0] for row in result]
    assert upns[0] == "smsadmin"
    assert result[0]["isAdmin"] is True
    assert set(upns) == {"smsadmin", "smsdefault", "fidouser"}  # fidouser has SMS as its default


def test_sms_list_catches_sms_only_user_without_sms_default():
    record = {"userPrincipalName": "x@d", "methodsRegistered": ["mobilePhone"], "defaultMfaMethod": "none"}
    result = am.sms_migration_list([record])
    assert len(result) == 1
    assert result[0]["reason"] == "SMS/voice is the only method"


def test_sms_list_ignores_authenticator_default(reg_details):
    upns = {row["userPrincipalName"] for row in am.sms_migration_list(reg_details)}
    assert not any(u.startswith(("pushadmin", "passkeyuser", "nothing")) for u in upns)


def test_admin_without_strong_mfa_is_flagged(reg_details):
    result = am.admins_without_strong_mfa(reg_details)
    assert [r["userPrincipalName"].split("@")[0] for r in result] == ["smsadmin"]
    assert result[0]["strongestMethod"] == "SMS / voice"


def test_admin_with_authenticator_is_not_flagged(reg_details):
    flagged = {r["userPrincipalName"] for r in am.admins_without_strong_mfa(reg_details)}
    assert not any(u.startswith("pushadmin") for u in flagged)
