"""Command-line entry point.

    python -m iam_insights.cli report            # all reports, summary at the top
    python -m iam_insights.cli report --csv      # also write each table to output/*.csv
    python -m iam_insights.cli cleanup --dry-run [--grace-days 30]
    python -m iam_insights.cli me                # /me and /me/authentication/methods
"""

import argparse
import sys
from collections import Counter

import pandas as pd

from iam_insights import auth_methods, cleanup, config, risky_signins
from iam_insights.sources import DataSource, GraphError, get_source


def collect(source: DataSource, grace_days: int = 30, today=None) -> dict:
    """Run every analysis once and return the results in one dict.

    Shared by the CLI and the Streamlit dashboard so they always agree.
    """
    users = source.get_users()
    reg = source.get_registration_details()
    sign_ins = source.get_sign_ins()

    sms = auth_methods.sms_migration_list(reg)
    findings = risky_signins.run_all_rules(users, sign_ins)
    stale = cleanup.find_stale_graduates(users, grace_days=grace_days, today=today)
    return {
        "users": users,
        "reg": reg,
        "sign_ins": sign_ins,
        "breakdown": auth_methods.method_breakdown(reg),
        "mfa_coverage": auth_methods.mfa_coverage(reg),
        "passwordless_rate": auth_methods.passwordless_rate(reg),
        "sms_list": sms,
        "sms_admins": sum(1 for row in sms if row["isAdmin"]),
        "weak_admins": auth_methods.admins_without_strong_mfa(reg),
        "findings": findings,
        "severity_counts": Counter(f["severity"] for f in findings),
        "rule_counts": Counter(f["rule"] for f in findings),
        "stale_graduates": stale,
        "plan": cleanup.plan_disable(stale),
        "grace_days": grace_days,
    }


def summary_lines(r: dict) -> list[str]:
    """The 4-line summary printed at the top of `report`."""
    sev = r["severity_counts"]
    return [
        f"Users: {len(r['users'])} | MFA coverage: {r['mfa_coverage']:.1f}% | "
        f"Passwordless-capable: {r['passwordless_rate']:.1f}%",
        f"SMS-default users to migrate: {len(r['sms_list'])} ({r['sms_admins']} admins)",
        f"Risky sign-in findings: {len(r['findings'])} (high: {sev.get('high', 0)}, medium: {sev.get('medium', 0)})",
        f"Graduated accounts still enabled past {r['grace_days']}-day grace: {len(r['stale_graduates'])}",
    ]


def _table(rows: list[dict], columns: list[str]) -> pd.DataFrame:
    """Rows -> DataFrame with a fixed column order (works even if rows is empty)."""
    return pd.DataFrame(rows, columns=columns)


def report_tables(r: dict) -> dict[str, pd.DataFrame]:
    """Every report section as a named table (also used for CSV export)."""
    breakdown = [{"strongestMethod": k, "users": v} for k, v in r["breakdown"].items()]
    sms = [{**row, "methodsRegistered": ", ".join(row["methodsRegistered"])} for row in r["sms_list"]]
    weak = [{**row, "methodsRegistered": ", ".join(row["methodsRegistered"])} for row in r["weak_admins"]]
    plan = [{"userPrincipalName": p["userPrincipalName"], "request": f"{p['method']} {p['url']}",
             "body": '{"accountEnabled": false}', "reason": p["reason"]} for p in r["plan"]]
    return {
        "auth_method_breakdown": _table(breakdown, ["strongestMethod", "users"]),
        "sms_migration_list": _table(sms, ["userPrincipalName", "userDisplayName", "isAdmin",
                                           "defaultMfaMethod", "methodsRegistered", "reason"]),
        "admins_without_strong_mfa": _table(weak, ["userPrincipalName", "userDisplayName",
                                                   "strongestMethod", "methodsRegistered"]),
        "risky_signins": _table(r["findings"], ["severity", "rule", "userPrincipalName",
                                                "createdDateTime", "detail", "signInId"]),
        "graduate_cleanup_plan": _table(plan, ["userPrincipalName", "request", "body", "reason"]),
    }


def _print_section(title: str, df: pd.DataFrame, max_rows: int | None = None):
    print(f"\n== {title} ({len(df)} rows) ==")
    if df.empty:
        print("(none)")
        return
    shown = df if max_rows is None else df.head(max_rows)
    print(shown.to_string(index=False))
    if max_rows is not None and len(df) > max_rows:
        print(f"... {len(df) - max_rows} more rows (use --csv for the full list)")


def cmd_report(args) -> int:
    source = get_source(args.source)
    r = collect(source, grace_days=args.grace_days)

    print(f"Data source: {source.name}")
    print("-" * 78)
    for line in summary_lines(r):
        print(line)
    print("-" * 78)

    tables = report_tables(r)
    _print_section("Authentication methods (strongest per user)", tables["auth_method_breakdown"])
    _print_section("SMS migration list (admins first)", tables["sms_migration_list"].drop(columns=["methodsRegistered"]),
                   max_rows=15)
    _print_section("Admins without strong MFA", tables["admins_without_strong_mfa"])
    print("\nRisky findings by rule: " + ", ".join(f"{k}: {v}" for k, v in sorted(r["rule_counts"].items())))
    _print_section("Risky sign-ins", tables["risky_signins"].drop(columns=["signInId"]), max_rows=30)
    _print_section(f"Graduate cleanup plan (dry run, {r['grace_days']}-day grace)", tables["graduate_cleanup_plan"])

    if args.csv:
        config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        for name, df in tables.items():
            df.to_csv(config.OUTPUT_DIR / f"{name}.csv", index=False)
        print(f"\nWrote {len(tables)} CSV files to {config.OUTPUT_DIR}")
    return 0


def cmd_cleanup(args) -> int:
    source = get_source(args.source)
    stale = cleanup.find_stale_graduates(source.get_users(), grace_days=args.grace_days)
    plan = cleanup.plan_disable(stale)

    print(f"Data source: {source.name} | grace period: {args.grace_days} days | dry run: {not args.apply}")
    print(f"{len(plan)} graduated accounts would be disabled:\n")
    for p in plan:
        print(f"  {p['method']} {p['url']}  body={{\"accountEnabled\": false}}  # {p['userPrincipalName']}: {p['reason']}")

    try:
        path = cleanup.apply_plan(plan, dry_run=not args.apply, source_name=source.name, confirm=args.confirm)
    except cleanup.CleanupRefused as err:
        print(f"\n{err}", file=sys.stderr)
        return 1
    print(f"\nDry run only: nothing was changed. Audit log written to {path}")
    return 0


def cmd_me(args) -> int:
    source = get_source(args.source)
    print(f"Data source: {source.name}")
    try:
        me = source.get_me()
        print(f"\nGET /me\n  displayName:       {me.get('displayName')}\n"
              f"  userPrincipalName: {me.get('userPrincipalName')}\n  id:                {me.get('id')}")
    except GraphError as err:
        print(f"\n{err}", file=sys.stderr)
        return 1
    try:
        methods = source.get_my_auth_methods()
        print(f"\nGET /me/authentication/methods ({len(methods)} methods)")
        for m in methods:
            print(f"  {m.get('@odata.type', '?').replace('#microsoft.graph.', '')}")
    except GraphError as err:
        # Not a crash: many organizations don't grant this permission to Graph Explorer.
        print(f"\n{err}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam_insights", description="Gryphon IAM Insights (synthetic data).")
    parser.add_argument("--source", choices=["mock", "graph"], default=None,
                        help="override DATA_SOURCE (default: from .env, else mock)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_report = sub.add_parser("report", help="print every report with a summary at the top")
    p_report.add_argument("--csv", action="store_true", help="also write each table to output/*.csv")
    p_report.add_argument("--grace-days", type=int, default=30, help="graduate grace period (default 30)")
    p_report.set_defaults(func=cmd_report)

    p_cleanup = sub.add_parser("cleanup", help="preview the graduate account cleanup")
    mode = p_cleanup.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True, help="plan only and write an audit log (default)")
    mode.add_argument("--apply", action="store_true", help="real run: always refused in mock, needs --confirm in graph")
    p_cleanup.add_argument("--confirm", action="store_true", help="required together with --apply in graph mode")
    p_cleanup.add_argument("--grace-days", type=int, default=30, help="days after graduation before disabling")
    p_cleanup.set_defaults(func=cmd_cleanup)

    p_me = sub.add_parser("me", help="show /me and /me/authentication/methods")
    p_me.set_defaults(func=cmd_me)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
