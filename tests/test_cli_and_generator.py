"""End-to-end checks: the CLI on the committed mock data, and the generator itself."""

from datetime import datetime, timezone

from iam_insights import cli, cleanup, generate_mock, risky_signins
from iam_insights.sources import MockSource

DATA_DATE = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)  # the date the mock data was generated for


def test_collect_on_mock_data_finds_planted_cases():
    r = cli.collect(MockSource(), today=DATA_DATE)
    assert len(r["users"]) == 200
    assert r["mfa_coverage"] == 95.0
    assert r["rule_counts"]["foreign_single_factor"] == 12
    assert r["rule_counts"]["password_spray_or_brute_force"] == 3
    assert r["rule_counts"]["impossible_travel"] == 1
    assert r["rule_counts"]["graduated_account_active"] >= 3
    assert len(r["stale_graduates"]) > 0
    assert len(r["plan"]) == len(r["stale_graduates"])


def test_summary_lines_format():
    r = cli.collect(MockSource(), today=DATA_DATE)
    lines = cli.summary_lines(r)
    assert lines[0].startswith("Users: 200 | MFA coverage: 95.0% | Passwordless-capable:")
    assert lines[1].startswith("SMS-default users to migrate:")
    assert lines[2].startswith("Risky sign-in findings:")
    assert lines[3].startswith("Graduated accounts still enabled past 30-day grace:")


def test_cli_report_with_csv(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "OUTPUT_DIR", tmp_path)
    assert cli.main(["--source", "mock", "report", "--csv"]) == 0
    out = capsys.readouterr().out
    assert "Users: 200" in out
    assert {p.name for p in tmp_path.iterdir()} == {
        "auth_method_breakdown.csv", "sms_migration_list.csv", "admins_without_strong_mfa.csv",
        "risky_signins.csv", "graduate_cleanup_plan.csv"}


def test_cli_cleanup_dry_run_writes_audit_log(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cleanup.config, "OUTPUT_DIR", tmp_path)
    assert cli.main(["--source", "mock", "cleanup", "--dry-run"]) == 0
    assert "Dry run only" in capsys.readouterr().out
    assert len(list(tmp_path.glob("audit_log_*.csv"))) == 1


def test_cli_cleanup_apply_refused_in_mock(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cleanup.config, "OUTPUT_DIR", tmp_path)
    assert cli.main(["--source", "mock", "cleanup", "--apply"]) == 1
    assert "dry run" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_cli_me_in_mock(capsys):
    assert cli.main(["--source", "mock", "me"]) == 0
    out = capsys.readouterr().out
    assert "GET /me" in out and "@mock.uoguelph.example" in out


def test_generator_is_deterministic():
    a = generate_mock.generate(60, seed=7)
    b = generate_mock.generate(60, seed=7)
    assert a == b


def test_generator_plants_cases_and_mix():
    users, reg, sign_ins = generate_mock.generate(200, seed=42)
    types = [u["employeeType"] for u in users]
    assert types.count("Student") == 140 and types.count("Graduated") == 20
    assert sum(1 for u in users if u["employeeType"] == "Graduated" and u["accountEnabled"]) == 12
    assert sum(1 for r in reg if r["isAdmin"]) == 3
    assert len(risky_signins.rule_foreign_single_factor(sign_ins)) == 12
    assert len(risky_signins.rule_password_spray_or_brute_force(sign_ins)) == 3
    assert len(risky_signins.rule_impossible_travel(sign_ins)) == 1


def test_generator_main_writes_files(tmp_path, capsys):
    generate_mock.main(["--users", "40", "--seed", "1", "--out", str(tmp_path)])
    assert {p.name for p in tmp_path.iterdir()} == {"users.json", "userRegistrationDetails.json", "signIns.json"}
    assert len(MockSource(tmp_path).get_users()) == 40
