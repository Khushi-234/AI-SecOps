"""
Incident View Component for ITS Dashboard.

Monitors active transportation incidents, severity classifications,
and traffic bottlenecks across the simulated road network.
Labeled with SIMULATION MODE.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from its.dashboard.services.its_dashboard_service import ITSDashboardService
from its.dashboard.styles.theme import render_badge, render_kpi_card


def render_incident_view(service: ITSDashboardService) -> None:
    """
    Renders the simulated Incident Monitoring tab.

    Args:
        service: Initialized ITSDashboardService instance.
    """
    st.markdown("### ⚠️ Simulated Incident Monitoring & Alerts")
    st.caption("Active traffic incidents, road hazard alerts, and emergency impact telemetry.")

    incidents = service.get_all_incidents()
    roads = {r.road_id: r for r in service.get_all_roads()}
    summary = service.incident_service.get_incident_summary()

    # KPI Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_kpi_card("Total Incidents", summary.get("total", len(incidents)), "Recorded in telemetry", "📋")
    with col2:
        active_cnt = summary.get("active", 0)
        render_kpi_card("Active Incidents", active_cnt, "Currently impacting flow", "🚨" if active_cnt > 0 else "✅")
    with col3:
        resolved_cnt = summary.get("resolved", 0)
        render_kpi_card("Resolved", resolved_cnt, "Cleared from network", "🟢")
    with col4:
        accidents_cnt = summary.get("ACCIDENT", 0)
        render_kpi_card("Accident Reports", accidents_cnt, "Collisions logged", "💥")

    st.markdown("---")

    # Filters
    col_f1, col_f2 = st.columns([1, 1])
    with col_f1:
        status_filter = st.selectbox(
            "Filter by Status:",
            options=["ALL", "ACTIVE", "RESOLVED"],
            index=1,  # Default to ACTIVE for SOC focus
        )
    with col_f2:
        severity_filter = st.selectbox(
            "Filter by Severity:",
            options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
        )

    # Filtered dataset
    filtered_incidents = []
    for inc in incidents:
        if status_filter != "ALL" and inc.status != status_filter:
            continue
        if severity_filter != "ALL" and inc.severity != severity_filter:
            continue
        filtered_incidents.append(inc)

    # Active Incident Alert Cards
    st.markdown("#### 🚨 Incident Alert Feed")
    if filtered_incidents:
        for inc in filtered_incidents:
            road = roads.get(inc.road_id)
            road_name = road.road_name if road else inc.road_id

            severity_color = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
            }.get(inc.severity, inc.severity)

            status_icon = "⚠️ ACTIVE" if inc.status == "ACTIVE" else "✅ RESOLVED"

            with st.container():
                st.markdown(
                    f"""
                    <div style="background: #1e293b; border-left: 4px solid {'#ef4444' if inc.severity in ['CRITICAL', 'HIGH'] else '#38bdf8'}; border-radius: 6px; padding: 14px 18px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-weight: 700; color: #f8fafc; font-size: 1.05rem;">{inc.incident_id} — {inc.incident_type}</span>
                            <span>
                                <span style="font-size: 0.8rem; font-weight: 600; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.08); margin-right: 6px;">{severity_color}</span>
                                <span style="font-size: 0.8rem; font-weight: 600; padding: 2px 8px; border-radius: 4px; background: {'rgba(239,68,68,0.2)' if inc.status == 'ACTIVE' else 'rgba(16,185,129,0.2)'}; color: {'#f87171' if inc.status == 'ACTIVE' else '#34d399'};">{status_icon}</span>
                            </span>
                        </div>
                        <div style="color: #cbd5e1; font-size: 0.9rem; margin-bottom: 6px;"><strong>Location:</strong> {road_name} ({inc.road_id})</div>
                        <div style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 6px;"><strong>Details:</strong> {inc.description}</div>
                        <div style="color: #64748b; font-size: 0.75rem;">Reported: {inc.timestamp}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.info("No incidents match the selected filter criteria.")

    # Tabular summary
    st.markdown("---")
    st.markdown("#### 📋 Incident Registry Table")
    table_rows = [
        {
            "Incident ID": inc.incident_id,
            "Road ID": inc.road_id,
            "Road Name": roads.get(inc.road_id).road_name if roads.get(inc.road_id) else inc.road_id,
            "Type": inc.incident_type,
            "Severity": inc.severity,
            "Status": inc.status,
            "Description": inc.description,
            "Timestamp": str(inc.timestamp),
        }
        for inc in filtered_incidents
    ]
    if table_rows:
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
