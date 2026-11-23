"""Feature 4: graduate account cleanup (the "leaver" step), dry run by default.

Nothing in this module ever sends a request. It only *plans* the Graph call
that would disable each account and writes an audit log of the plan.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path

from iam_insights import config
from iam_insights.risky_signins import parse_time

AUDIT_COLUMNS = ["timestamp", "userPrincipalName", "action", "reason", "dry_run"]


class CleanupRefused(Exception):
    """Raised when a real (non-dry-run) cleanup is attempted without safeguards."""


def find_stale_graduates(users: list[dict], grace_days: int = 30, today: datetime | None = None) -> list[dict]:
    """Graduated, still enabled, and graduated more than `grace_days` ago.

    The grace period gives graduates time to save their files. `today` can be
    passed in so tests always get the same answer.
    """
    today = today or datetime.now(timezone.utc)
    stale = []
    for u in users:
        leave = u.get("employeeLeaveDateTime")
        if u.get("employeeType") != "Graduated" or u.get("accountEnabled") is not True or not leave:
            continue
        days_since = (today - parse_time(leave)).days
        if days_since > grace_days:
            stale.append({**u, "daysSinceGraduation": days_since})
    return sorted(stale, key=lambda u: u["daysSinceGraduation"], reverse=True)


def plan_disable(users: list[dict]) -> list[dict]:
    """For each user, the exact Graph request that *would* disable the account."""
    return [
        {
            "userPrincipalName": u["userPrincipalName"],
            "method": "PATCH",
            "url": f"/users/{u['id']}",
            "body": {"accountEnabled": False},
            "reason": (f"Graduated {u['daysSinceGraduation']} days ago; account still enabled"
                       if "daysSinceGraduation" in u else "Graduated; account still enabled"),
        }
        for u in users
    ]


def apply_plan(plan: list[dict], dry_run: bool = True, source_name: str = "mock", confirm: bool = False,
               output_dir: Path | str | None = None, now: datetime | None = None) -> Path:
    """Write every planned action to output/audit_log_<timestamp>.csv and return the path.

    * Mock mode: dry run is the only mode, so a real run is refused.
    * Graph mode: a real run also needs confirm=True (the --confirm flag) and
      User.ReadWrite.All. This project never sends the PATCH; it stops at the
      audit log on purpose.
    """
    if not dry_run:
        if source_name == "mock":
            raise CleanupRefused("Mock mode only supports a dry run. Nothing was changed.")
        if not confirm:
            raise CleanupRefused(
                "Refusing to disable real accounts without --confirm. This needs the admin-only "
                "User.ReadWrite.All permission and should never run against a real tenant from this project.")
        raise CleanupRefused(
            "WARNING: real cleanup is deliberately not implemented in this learning project. "
            "Review the dry-run audit log and apply changes through your normal change process.")

    now = now or datetime.now(timezone.utc)
    folder = Path(output_dir) if output_dir else config.OUTPUT_DIR
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"audit_log_{now.strftime('%Y%m%dT%H%M%SZ')}.csv"

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=AUDIT_COLUMNS)
        writer.writeheader()
        for action in plan:
            writer.writerow({
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "userPrincipalName": action["userPrincipalName"],
                "action": f"{action['method']} {action['url']} {{\"accountEnabled\": false}}",
                "reason": action["reason"],
                "dry_run": dry_run,
            })
    return path
