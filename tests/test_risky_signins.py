from conftest import failures, sign_in

from iam_insights import risky_signins as rs

FINDING_KEYS = {"rule", "userPrincipalName", "signInId", "createdDateTime", "detail", "severity"}


def ids(findings):
    return [f["signInId"] for f in findings]


def test_foreign_single_factor_fires_on_planted_case(sign_ins):
    result = rs.rule_foreign_single_factor(sign_ins)
    assert ids(result) == ["s-foreign"]
    assert result[0]["severity"] == "high"
    assert "Lagos, NG" in result[0]["detail"]


def test_foreign_sign_in_with_mfa_is_not_flagged(sign_ins):
    assert "s-foreign-mfa" not in ids(rs.rule_foreign_single_factor(sign_ins))


def test_safe_canadian_mfa_sign_in_creates_no_finding():
    safe = [sign_in("safe", "alice", "2026-11-20T09:00:00Z")]
    assert rs.run_all_rules([], safe) == []


def test_brute_force_fires_on_five_failures(sign_ins):
    result = rs.rule_password_spray_or_brute_force(sign_ins)
    assert [f["userPrincipalName"].split("@")[0] for f in result] == ["carol"]
    assert result[0]["severity"] == "high"
    assert result[0]["detail"].startswith("5 failed sign-ins")


def test_brute_force_four_failures_do_not_fire():
    assert rs.rule_password_spray_or_brute_force(failures("d", "dave", 0, 4)) == []


def test_brute_force_respects_window():
    # 5 failures, 3 minutes apart = 12 minutes total, outside a 10-minute window.
    spread = failures("w", "wendy", 0, 5, step_seconds=180)
    assert rs.rule_password_spray_or_brute_force(spread) == []
    # ...but inside a 15-minute window.
    assert len(rs.rule_password_spray_or_brute_force(spread, window_minutes=15)) == 1


def test_brute_force_threshold_is_a_parameter():
    four = failures("d", "dave", 0, 4)
    assert len(rs.rule_password_spray_or_brute_force(four, threshold=4)) == 1


def test_brute_force_reports_one_finding_per_burst():
    assert len(rs.rule_password_spray_or_brute_force(failures("b", "burst", 0, 12))) == 1


def test_impossible_travel_fires(sign_ins):
    result = rs.rule_impossible_travel(sign_ins)
    assert ids(result) == ["t2"]
    assert result[0]["severity"] == "medium"
    assert "Guelph, CA then London, GB" in result[0]["detail"]


def test_impossible_travel_ignores_five_hours_apart():
    pair = [sign_in("f1", "frank", "2026-11-17T08:00:00Z"),
            sign_in("f2", "frank", "2026-11-17T13:00:00Z", "US", "Chicago")]
    assert rs.rule_impossible_travel(pair) == []


def test_impossible_travel_handles_unsorted_input():
    pair = [sign_in("b", "erin", "2026-11-18T13:00:00Z", "GB", "London"),
            sign_in("a", "erin", "2026-11-18T12:00:00Z")]
    assert ids(rs.rule_impossible_travel(pair)) == ["b"]


def test_graduated_account_active_fires_on_success_only(users, sign_ins):
    result = rs.rule_graduated_account_active(users, sign_ins)
    assert ids(result) == ["g1"]  # g2 was a failed sign-in
    assert result[0]["severity"] == "medium"


def test_run_all_rules_sorted_by_severity_then_time(users, sign_ins):
    result = rs.run_all_rules(users, sign_ins)
    assert len(result) == 4
    assert [f["severity"] for f in result] == ["high", "high", "medium", "medium"]
    # Newest first within each severity.
    assert result[0]["createdDateTime"] > result[1]["createdDateTime"]
    assert result[2]["createdDateTime"] > result[3]["createdDateTime"]
    assert all(set(f) == FINDING_KEYS for f in result)
