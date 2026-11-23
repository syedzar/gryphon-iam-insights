"""Streamlit dashboard for Gryphon IAM Insights.

Run:  streamlit run app/dashboard.py

Read-only by design: there is no button that applies changes. The cleanup
section only previews the PATCH requests and lets you download the audit log.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Make the iam_insights package importable when run as `streamlit run app/dashboard.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iam_insights.cli import collect, report_tables  # noqa: E402
from iam_insights.sources import get_source  # noqa: E402

BAR_COLOUR = "#4C6A92"  # one neutral slate blue for every chart (no university branding)

st.set_page_config(page_title="IAM Insights (synthetic)", layout="wide")


@st.cache_data(ttl=300)
def load(grace_days: int):
    """Fetch and analyse the data once, then cache it for 5 minutes."""
    source = get_source()
    results = collect(source, grace_days=grace_days)
    notices = list(getattr(source, "messages", []))
    loaded_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return source.name, results, notices, loaded_at


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("IAM Insights")
    grace_days = st.number_input("Graduate grace period (days)", min_value=0, max_value=365, value=30, step=5)
    if st.button("Refresh data"):
        load.clear()

source_name, r, notices, loaded_at = load(int(grace_days))
tables = report_tables(r)

with st.sidebar:
    st.markdown(f"**Data source:** `{source_name}`")
    st.markdown(f"**Last refresh:** {loaded_at}")
    for note in notices:
        st.info(note)
    st.divider()
    st.caption("Synthetic data. Learning project.")

st.title("Identity and access insights")

# ---------------------------------------------------------------------------
# 1. Metric tiles
# ---------------------------------------------------------------------------
# Two rows of three, so the labels stay readable on narrow screens.
row1, row2 = st.columns(3), st.columns(3)
row1[0].metric("Users", len(r["users"]), border=True)
row1[1].metric("MFA coverage", f"{r['mfa_coverage']:.1f}%", border=True)
row1[2].metric("Passwordless-capable", f"{r['passwordless_rate']:.1f}%", border=True)
row2[0].metric("SMS-default users", len(r["sms_list"]), border=True)
row2[1].metric("Risky findings", len(r["findings"]), border=True)
row2[2].metric("Stale graduate accounts", len(r["stale_graduates"]), border=True)

# ---------------------------------------------------------------------------
# 2. Authentication methods
# ---------------------------------------------------------------------------
st.subheader("Authentication methods")
st.caption("Each user is counted once, by the strongest method they have registered.")
breakdown = tables["auth_method_breakdown"].sort_values("users", ascending=True)
fig = px.bar(breakdown, x="users", y="strongestMethod", orientation="h", text="users",
             labels={"users": "Users", "strongestMethod": ""})
fig.update_traces(marker_color=BAR_COLOUR, textposition="outside", cliponaxis=False)
fig.update_layout(height=320, margin=dict(l=0, r=30, t=10, b=0))
st.plotly_chart(fig, width="stretch")

# ---------------------------------------------------------------------------
# 3. SMS migration list
# ---------------------------------------------------------------------------
st.subheader("SMS migration list")
st.caption(f"{len(r['sms_list'])} users rely on SMS/voice ({r['sms_admins']} admins, listed first). "
           "Move them to Authenticator or a passkey.")
sms_df = tables["sms_migration_list"]
st.dataframe(sms_df, width="stretch", hide_index=True)
st.download_button("Download SMS list (CSV)", sms_df.to_csv(index=False), "sms_migration_list.csv", "text/csv")

if r["weak_admins"]:
    st.warning(f"{len(r['weak_admins'])} admins have no passkey, FIDO2 key or Authenticator registered.")
    st.dataframe(tables["admins_without_strong_mfa"], width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# 4. Risky sign-ins
# ---------------------------------------------------------------------------
st.subheader("Risky sign-ins")
left, right = st.columns([2, 1])
with left:
    severities = st.multiselect("Severity", ["high", "medium"], default=["high", "medium"])
    risky_df = tables["risky_signins"]
    st.dataframe(risky_df[risky_df["severity"].isin(severities)], width="stretch", hide_index=True)
with right:
    by_rule = pd.DataFrame(sorted(r["rule_counts"].items(), key=lambda kv: kv[1]), columns=["rule", "findings"])
    fig = px.bar(by_rule, x="findings", y="rule", orientation="h", text="findings",
                 labels={"findings": "Findings", "rule": ""})
    fig.update_traces(marker_color=BAR_COLOUR, textposition="outside", cliponaxis=False)
    fig.update_layout(height=280, margin=dict(l=0, r=30, t=10, b=0))
    st.plotly_chart(fig, width="stretch")

# ---------------------------------------------------------------------------
# 5. Graduate cleanup preview (read-only)
# ---------------------------------------------------------------------------
st.subheader("Graduate cleanup preview")
st.caption(f"Graduated students whose accounts are still enabled more than {r['grace_days']} days after "
           "graduation. These are the Graph requests that *would* be sent. Nothing is applied from here.")
plan_df = tables["graduate_cleanup_plan"]
st.dataframe(plan_df, width="stretch", hide_index=True)

audit = pd.DataFrame([{
    "timestamp": loaded_at,
    "userPrincipalName": p["userPrincipalName"],
    "action": f"{p['method']} {p['url']} {{\"accountEnabled\": false}}",
    "reason": p["reason"],
    "dry_run": True,
} for p in r["plan"]], columns=["timestamp", "userPrincipalName", "action", "reason", "dry_run"])
st.download_button("Download audit log (CSV)", audit.to_csv(index=False), "audit_log_dry_run.csv", "text/csv")
