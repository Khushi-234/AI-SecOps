"""
Tables & Request Details component for Streamlit Security Dashboard.
"""

from __future__ import annotations

import json
import pandas as pd
import streamlit as st
from typing import Any, Dict, List, Optional
from database.models.audit_event import AuditEvent
from dashboard.config import PIPELINE_STAGES



def render_request_monitoring_table(requests: List[Dict[str, Any]]) -> Optional[str]:
    """
    Renders recent requests monitoring table with status indicators and cards.
    Returns selected request_id if clicked for investigation.
    """
    if not requests:
        st.info("No request audit events found matching the specified filter criteria.")
        return None

    st.markdown("### 📜 Request History Overview")
    
    # Render visual cards for top requests matching requirement 5
    for req in requests[:10]:
        req_id = req["request_id"]
        status = str(req.get("status", "ALLOWED")).upper()
        is_blocked = status in ("BLOCKED", "FAIL_SECURE", "FAIL_SECURE_BLOCKED")
        
        status_label = "BLOCKED" if is_blocked else "ALLOWED"
        status_color = "#EF4444" if is_blocked else "#10B981"
        status_bg = "rgba(239, 68, 68, 0.12)" if is_blocked else "rgba(16, 185, 129, 0.12)"
        status_border = "rgba(239, 68, 68, 0.35)" if is_blocked else "rgba(16, 185, 129, 0.35)"
        
        comp = req.get("blocked_by")
        if not comp:
            comps_raw = req.get("components", "")
            comp = comps_raw.split(", ")[-1] if comps_raw else "OutputGuard"

        risk_score = float(req.get("risk_score", 0.0))
        ts_str = str(req.get("timestamp", ""))
        if "T" in ts_str:
            ts_str = ts_str.replace("T", " ")[:19]
        elif "+" in ts_str:
            ts_str = ts_str.split("+")[0][:19]

        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid {status_border}; border-radius: 0.75rem; padding: 1rem 1.25rem; margin-bottom: 0.85rem; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                    <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 1.05rem; color: #F8FAFC;">{req_id}</span>
                    <span style="background: {status_bg}; color: {status_color}; border: 1px solid {status_border}; font-weight: 800; font-size: 0.8rem; padding: 0.25rem 0.65rem; border-radius: 0.4rem; font-family: 'JetBrains Mono', monospace;">{status_label}</span>
                </div>
                <div style="font-size: 0.95rem; color: #94A3B8; margin-bottom: 0.35rem;">
                    <strong style="color: #CBD5E1;">Stage / Component:</strong> <span style="color: #38BDF8; font-family: 'JetBrains Mono', monospace;">{comp}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 0.88rem; color: #64748B;">
                    <span>Risk Score: <strong style="color: {status_color}; font-family: 'JetBrains Mono', monospace;">{risk_score:.2f}</strong></span>
                    <span style="font-family: 'JetBrains Mono', monospace; color: #94A3B8;">📅 {ts_str}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 🔍 Live Request Activity Monitor")

    df_requests = pd.DataFrame(requests)

    # Format columns for display
    display_df = df_requests[
        [
            "request_id",
            "timestamp",
            "status",
            "severity",
            "action",
            "event_count",
            "components",
        ]
    ].copy()

    display_df.rename(
        columns={
            "request_id": "Request ID",
            "timestamp": "Last Event Time",
            "status": "Status",
            "severity": "Severity",
            "action": "Action",
            "event_count": "Events",
            "components": "Stages Passed",
        },
        inplace=True,
    )

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Request ID": st.column_config.TextColumn("Request ID", width="medium"),
            "Last Event Time": st.column_config.TextColumn("Last Event Time", width="medium"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Action": st.column_config.TextColumn("Action", width="small"),
            "Events": st.column_config.NumberColumn("Events", width="small"),
            "Stages Passed": st.column_config.TextColumn("Stages Passed", width="large"),
        },
    )

    st.markdown("---")
    st.markdown("### 🕵️ Deep Request Inspection")
    request_ids = [r["request_id"] for r in requests]
    selected_req = st.selectbox(
        "Select Request ID to inspect full 8-stage security lifecycle:",
        options=["-- Select Request ID --"] + request_ids,
        key="request_selector",
    )

    if selected_req and selected_req != "-- Select Request ID --":
        return selected_req

    return None


def render_request_lifecycle(events: List[AuditEvent]) -> None:
    """
    Visualizes full 8-stage pipeline execution lifecycle for a selected request.
    """
    if not events:
        st.warning("No audit events recorded for the selected request.")
        return

    req_id = events[0].request_id
    trc_id = events[0].trace_id
    is_blocked = any(e.status == "BLOCKED" or e.action == "BLOCK" for e in events)

    st.markdown(f"#### Request Investigation: `{req_id}`")
    st.caption(f"Trace ID: `{trc_id}` | Event Count: `{len(events)}`")

    if is_blocked:
        blocking_event = next(
            (e for e in events if e.status == "BLOCKED" or e.action == "BLOCK"),
            events[-1],
        )
        st.error(
            f"🚫 **REQUEST BLOCKED** at stage **{blocking_event.component}**\n\n"
            f"• **Severity**: `{blocking_event.severity}`\n\n"
            f"• **Reason**: {blocking_event.message}"
        )
    else:
        st.success("✅ **REQUEST EXECUTED SUCCESSFULLY** — Passed all active pipeline stages.")

    st.markdown("##### 📌 Pipeline Execution Lifecycle")

    # Map events by stage component
    stage_events = {e.component: e for e in events}

    cols = st.columns(len(PIPELINE_STAGES))
    for idx, stage_name in enumerate(PIPELINE_STAGES):
        with cols[idx]:
            if stage_name in stage_events:
                evt = stage_events[stage_name]
                if evt.status == "BLOCKED" or evt.action == "BLOCK":
                    st.markdown(
                        f"❌ **{stage_name}**\n\n`BLOCKED`",
                        help=f"Severity: {evt.severity}\nMsg: {evt.message}",
                    )
                else:
                    st.markdown(
                        f"✅ **{stage_name}**\n\n`PASSED`",
                        help=f"Action: {evt.action}\nMsg: {evt.message}",
                    )
            else:
                st.markdown(
                    f"⚪ **{stage_name}**\n\n`SKIPPED`",
                    help="Stage skipped due to early exit or pipeline flow.",
                )

    st.markdown("##### 📜 Step-by-Step Audit Timeline")
    for idx, evt in enumerate(events, 1):
        status_icon = "🛑" if (evt.status == "BLOCKED" or evt.action == "BLOCK") else "🛡️"
        with st.expander(
            f"{status_icon} Stage {idx}: [{evt.component}] - Action: [{evt.action}] - Status: [{evt.status}] ({evt.timestamp.strftime('%H:%M:%S.%f')[:-3]})"
        ):
            st.markdown(f"**Event ID**: `{evt.event_id}`")
            st.markdown(f"**Event Type**: `{evt.event_type}`")
            st.markdown(f"**Severity**: `{evt.severity}`")
            st.markdown(f"**Summary Message**: {evt.message}")

            if evt.metadata:
                st.markdown("**Sanitized Audit Metadata:**")
                st.json(evt.metadata)
