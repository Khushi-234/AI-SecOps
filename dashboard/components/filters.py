"""
Filters & Controls component for Streamlit Security Dashboard.
"""

from __future__ import annotations

import streamlit as st
from typing import Any, Dict
from dashboard.config import PIPELINE_STAGES

def render_sidebar_filters() -> Dict[str, Any]:
    """
    Renders sidebar filtering controls for database queries.
    Returns filter selections dictionary applied via the '→ Apply Filters' button.
    """
    if "applied_filters" not in st.session_state:
        st.session_state["applied_filters"] = {
            "request_id": None,
            "status": None,
            "severity": None,
            "component": None,
            "limit": 50,
        }

    st.sidebar.title("🛡️ Controls & Filters")

    # Refresh Control
    if st.sidebar.button("🔄 Refresh Real-Time Audit Data", use_container_width=True, key="btn_refresh_audit_data"):
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.subheader("🔍 Query Filters")

    applied = st.session_state["applied_filters"]
    current_req_id = applied.get("request_id") or ""
    current_status = applied.get("status") or "ALL"
    current_severity = applied.get("severity") or "ALL"
    current_component = applied.get("component") or "ALL"
    current_limit = applied.get("limit") or 50

    status_options = ["ALL", "SUCCESS", "BLOCKED", "FAIL_SECURE", "ALLOWED"]
    severity_options = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    component_options = ["ALL"] + PIPELINE_STAGES
    limit_options = [10, 25, 50, 100, 250]

    status_idx = status_options.index(current_status) if current_status in status_options else 0
    severity_idx = severity_options.index(current_severity) if current_severity in severity_options else 0
    component_idx = component_options.index(current_component) if current_component in component_options else 0

    req_search = st.sidebar.text_input(
        "Request ID Search:",
        value=current_req_id,
        placeholder="e.g. req_d9e3030a4be2",
        help="Search for a specific request correlation ID.",
        key="widget_filter_req_id",
    )

    status_opt = st.sidebar.selectbox(
        "Request Status:",
        options=status_options,
        index=status_idx,
        key="widget_filter_status",
    )

    severity_opt = st.sidebar.selectbox(
        "Threat Severity:",
        options=severity_options,
        index=severity_idx,
        key="widget_filter_severity",
    )

    component_opt = st.sidebar.selectbox(
        "Pipeline Component:",
        options=component_options,
        index=component_idx,
        key="widget_filter_component",
    )

    row_limit = st.sidebar.select_slider(
        "Display Record Limit:",
        options=limit_options,
        value=current_limit if current_limit in limit_options else 50,
        key="widget_filter_limit",
    )

    # Attractive Apply Filters button
    apply_clicked = st.sidebar.button(
        "→ Apply Filters",
        type="primary",
        use_container_width=True,
        key="btn_apply_filters",
    )

    if apply_clicked:
        st.session_state["applied_filters"] = {
            "request_id": req_search.strip() if req_search.strip() else None,
            "status": None if status_opt == "ALL" else status_opt,
            "severity": None if severity_opt == "ALL" else severity_opt,
            "component": None if component_opt == "ALL" else component_opt,
            "limit": row_limit,
        }
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("🛡️ AISECOPS Security Runtime")

    return st.session_state["applied_filters"]
