"""
Visualizations & Charts component for Streamlit Security Dashboard.
"""

from __future__ import annotations

import plotly.express as px
import pandas as pd
import streamlit as st
from typing import Any, Dict



def render_analytics_charts(analytics_data: Dict[str, Any]) -> None:
    """
    Renders security analytics charts from PostgreSQL breakdown data.
    """
    st.markdown("### 📊 Security Threat Analytics")

    col1, col2 = st.columns(2)

    # 1. Allowed vs Blocked Status Distribution
    status_data = analytics_data.get("status", {})
    if status_data:
        df_status = pd.DataFrame(
            [{"Status": k, "Count": v} for k, v in status_data.items()]
        )
        fig_status = px.pie(
            df_status,
            names="Status",
            values="Count",
            title="Request Decision Status Distribution",
            color="Status",
            color_discrete_map={
                "SUCCESS": "#10B981",
                "ALLOWED": "#10B981",
                "BLOCKED": "#EF4444",
                "FAIL_SECURE": "#F59E0B",
                "WARNING": "#F59E0B",
            },
            hole=0.4,
        )
        fig_status.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
        )
        with col1:
            st.plotly_chart(fig_status, use_container_width=True)
    else:
        with col1:
            st.info("No status data recorded yet.")

    # 2. Threat Severity Breakdown
    sev_data = analytics_data.get("severity", {})
    if sev_data:
        df_sev = pd.DataFrame(
            [{"Severity": k, "Count": v} for k, v in sev_data.items()]
        )
        fig_sev = px.bar(
            df_sev,
            x="Severity",
            y="Count",
            title="Audit Events by Severity Level",
            color="Severity",
            color_discrete_map={
                "INFO": "#3B82F6",
                "LOW": "#10B981",
                "MEDIUM": "#F59E0B",
                "HIGH": "#EF4444",
                "CRITICAL": "#991B1B",
            },
            text_auto=True,
        )
        fig_sev.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
            showlegend=False,
        )
        with col2:
            st.plotly_chart(fig_sev, use_container_width=True)
    else:
        with col2:
            st.info("No severity data recorded yet.")

    col3, col4 = st.columns(2)

    # 3. Events by Security Component
    comp_data = analytics_data.get("component", {})
    if comp_data:
        df_comp = pd.DataFrame(
            [{"Component": k, "Count": v} for k, v in comp_data.items()]
        )
        fig_comp = px.bar(
            df_comp,
            x="Count",
            y="Component",
            orientation="h",
            title="Audit Events by Pipeline Component Stage",
            color="Count",
            color_continuous_scale="Viridis",
            text_auto=True,
        )
        fig_comp.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
            yaxis=dict(autorange="reversed"),
        )
        with col3:
            st.plotly_chart(fig_comp, use_container_width=True)
    else:
        with col3:
            st.info("No component data recorded yet.")

    # 4. Action Decision Breakdown
    act_data = analytics_data.get("action", {})
    if act_data:
        df_act = pd.DataFrame(
            [{"Action": k, "Count": v} for k, v in act_data.items()]
        )
        fig_act = px.pie(
            df_act,
            names="Action",
            values="Count",
            title="Enforcement Action Distribution",
            color="Action",
            color_discrete_map={
                "ALLOW": "#10B981",
                "WARN": "#F59E0B",
                "BLOCK": "#EF4444",
                "HARDEN": "#6366F1",
                "REDACT": "#8B5CF6",
            },
        )
        fig_act.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
        )
        with col4:
            st.plotly_chart(fig_act, use_container_width=True)
    else:
        with col4:
            st.info("No action data recorded yet.")
