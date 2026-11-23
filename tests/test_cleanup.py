import csv

import pytest

from iam_insights import cleanup


def names(rows):
    return [r["userPrincipalName"].split("@")[0] for r in rows]


def test_graduate_inside_grace_period_is_not_flagged(users, today):
    assert "grad10" not in names(cleanup.find_stale_graduates(users, today=today))


def test_graduate_45_days_ago_is_flagged(users, today):
    stale = cleanup.find_stale_graduates(users, today=today)
    assert "grad45" in names(stale)
    assert next(u for u in stale if u["userPrincipalName"].startswith("grad45"))["daysSinceGraduation"] == 45


def test_stale_list_is_oldest_first(users, today):
    assert names(cleanup.find_stale_graduates(users, today=today)) == ["grad200", "grad45"]


def test_disabled_graduate_is_ignored(users, today):
    assert "graddisabled" not in names(cleanup.find_stale_graduates(users, today=today))


def test_non_graduates_are_ignored(users, today):
    assert not {"alice", "bob"} & set(names(cleanup.find_stale_graduates(users, today=today)))


def test_grace_days_is_configurable(users, today):
    assert names(cleanup.find_stale_graduates(users, grace_days=5, today=today)) == ["grad200", "grad45", "grad10"]
    assert names(cleanup.find_stale_graduates(users, grace_days=100, today=today)) == ["grad200"]


def test_plan_builds_correct_patch(users, today):
    plan = cleanup.plan_disable(cleanup.find_stale_graduates(users, today=today))
    assert len(plan) == 2
    first = plan[0]
    assert first["method"] == "PATCH"
    assert first["url"] == "/users/id-grad200"
    assert first["body"] == {"accountEnabled": False}
    assert "200 days" in first["reason"]


def test_dry_run_writes_audit_csv_with_right_columns(users, today, tmp_path):
    plan = cleanup.plan_disable(cleanup.find_stale_graduates(users, today=today))
    path = cleanup.apply_plan(plan, output_dir=tmp_path, now=today)

    assert path.name == "audit_log_20261122T120000Z.csv"
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0].keys()) == ["timestamp", "userPrincipalName", "action", "reason", "dry_run"]
    assert len(rows) == 2
    assert rows[0]["dry_run"] == "True"
    assert rows[0]["action"].startswith("PATCH /users/id-grad200")


def test_dry_run_is_the_default(users, today, tmp_path):
    path = cleanup.apply_plan([], output_dir=tmp_path, now=today)
    assert path.exists()


def test_real_apply_in_mock_mode_refuses(tmp_path):
    with pytest.raises(cleanup.CleanupRefused, match="dry run"):
        cleanup.apply_plan([], dry_run=False, source_name="mock", output_dir=tmp_path)


def test_real_apply_in_graph_mode_without_confirm_refuses(tmp_path):
    with pytest.raises(cleanup.CleanupRefused, match="--confirm"):
        cleanup.apply_plan([], dry_run=False, source_name="graph", confirm=False, output_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []  # nothing written


def test_real_apply_in_graph_mode_with_confirm_still_does_not_send(tmp_path):
    with pytest.raises(cleanup.CleanupRefused, match="WARNING"):
        cleanup.apply_plan([], dry_run=False, source_name="graph", confirm=True, output_dir=tmp_path)
