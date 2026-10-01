"""
Metric Cards component for Streamlit Security Dashboard.
"""

from __future__ import annotations

import streamlit as st
from typing import Any, Dict

def render_kpi_metrics(metrics: Dict[str, Any]) -> None:
    """
    Renders top-level security metric cards.
    """
    col1, col2, col3, col4, col5 = st.columns(5)

    tot_req = metrics.get("total_requests", 0)
    alw_req = metrics.get("allowed_requests", 0)
    blk_req = metrics.get("blocked_requests", 0)
    tot_evt = metrics.get("total_events", 0)
    crit_evt = metrics.get("critical_high_events", 0)

    block_rate = (blk_req / tot_req * 100) if tot_req > 0 else 0.0

    with col1:
        st.metric(
            label="Total Requests",
            value=f"{tot_req:,}",
            help="Total unique prompt requests processed by AI-SecOps pipeline.",
        )

    with col2:
        st.metric(
            label="Allowed Requests",
            value=f"{alw_req:,}",
            delta=f"{(alw_req/tot_req*100):.1f}%" if tot_req > 0 else None,
            delta_color="normal",
            help="Requests passed cleanly through all 8 security guardrail stages.",
        )

    with col3:
        st.metric(
            label="Blocked Requests",
            value=f"{blk_req:,}",
            delta=f"{block_rate:.1f}% blocked" if tot_req > 0 else None,
            delta_color="inverse",
            help="Requests halted due to prompt injection, jailbreak, or security policy override.",
        )

    with col4:
        st.metric(
            label="Critical / High Threats",
            value=f"{crit_evt:,}",
            delta="Security Alert" if crit_evt > 0 else "Clean",
            delta_color="inverse" if crit_evt > 0 else "normal",
            help="Audit events flagged with CRITICAL or HIGH severity.",
        )

    with col5:
        st.metric(
            label="Persisted Audit Events",
            value=f"{tot_evt:,}",
            help="Total immutable audit logs recorded in PostgreSQL database.",
        )
