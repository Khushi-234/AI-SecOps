"""
Traffic View Component for ITS Dashboard.

Renders simulated network KPIs, congestion breakdown, and road-level telemetry.
Labeled with SIMULATION MODE.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from its.dashboard.services.its_dashboard_service import ITSDashboardService
from its.dashboard.styles.theme import render_badge, render_kpi_card


def render_traffic_view(service: ITSDashboardService) -> None:
    """
    Renders the simulated Traffic Network Overview tab.

    Args:
        service: Initialized ITSDashboardService instance.
    """
    st.markdown("### 🚦 Simulated Traffic Network Overview")
    st.caption("Live monitoring of simulated road segments, average flow speeds, and congestion telemetry.")

    kpis = service.get_network_kpis()

    # Top KPI metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        render_kpi_card("Total Roads", kpis["total_roads"], "Simulated network", "🛣️")
    with col2:
        render_kpi_card("Monitored Segments", kpis["monitored_segments"], "Active sensors", "📡")
    with col3:
        render_kpi_card("Network Avg Speed", f"{kpis['average_speed_kmh']} km/h", "Flow rate", "⚡")
    with col4:
        render_kpi_card("Total Vehicle Count", f"{kpis['total_vehicles']:,}", "Current volume", "🚗")
    with col5:
        crit_count = kpis["critical_congestion_count"]
        render_kpi_card(
            "Critical Congestion",
            crit_count,
            "Segments requiring alert",
            "⚠️" if crit_count > 0 else "✅",
        )

    st.markdown("---")

    # Filter and Search
    traffic_records = service.get_all_traffic()
    roads = {r.road_id: r for r in service.get_all_roads()}

    col_filter1, col_filter2 = st.columns([1, 2])
    with col_filter1:
        congestion_filter = st.selectbox(
            "Filter by Congestion Level:",
            options=["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=0,
        )
    with col_filter2:
        search_query = st.text_input("Search Road Name:", placeholder="e.g., SG Highway, Ring Road...")

    # Data transformation
    table_data = []
    for tc in traffic_records:
        road = roads.get(tc.road_id)
        road_name = road.road_name if road else tc.road_id
        road_type = road.road_type if road else "N/A"
        speed_limit = road.speed_limit if road else 0

        # Apply filters
        if congestion_filter != "ALL" and tc.congestion_level != congestion_filter:
            continue
        if search_query and search_query.lower() not in road_name.lower():
            continue

        table_data.append({
            "Road ID": tc.road_id,
            "Road Name": road_name,
            "Type": road_type,
            "Congestion": tc.congestion_level,
            "Avg Speed (km/h)": f"{tc.average_speed:.1f}",
            "Speed Limit (km/h)": speed_limit,
            "Vehicle Count": tc.vehicle_count,
            "Sensor Health": getattr(tc, "sensor_health", "NORMAL (SIMULATED)"),
            "Last Updated": tc.timestamp.strftime("%Y-%m-%d %H:%M:%S") if hasattr(tc.timestamp, "strftime") else str(tc.timestamp),
        })

    df = pd.DataFrame(table_data)

    st.markdown("#### 📊 Monitored Road Segments Telemetry Table")
    if not df.empty:
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No road segments match the selected filter criteria.")

    # Congestion Distribution Summary
    st.markdown("#### 📈 Congestion Level Distribution")
    summary = service.traffic_service.get_traffic_summary()
    dist_cols = st.columns(4)
    with dist_cols[0]:
        st.metric("LOW Congestion", f"{summary.get('LOW', 0)} roads", help="Smooth flowing traffic")
    with dist_cols[1]:
        st.metric("MEDIUM Congestion", f"{summary.get('MEDIUM', 0)} roads", help="Moderate vehicle density")
    with dist_cols[2]:
        st.metric("HIGH Congestion", f"{summary.get('HIGH', 0)} roads", help="Heavy congestion observed")
    with dist_cols[3]:
        st.metric("CRITICAL Congestion", f"{summary.get('CRITICAL', 0)} roads", help="Severe bottlenecks or gridlock")
