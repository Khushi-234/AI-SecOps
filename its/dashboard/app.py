"""
ITS Dashboard — Intelligent Transportation System Security Operations Center (SOC).

Main Streamlit Application Entry Point.
Demonstrates both Intelligent Transportation System domain functionality
and secure AI transportation assistance mediated by the frozen AI-SecOps framework.

ENVIRONMENT: SIMULATION MODE (Simulated ITS Telemetry).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

import importlib
import its.dashboard.components.assistant_view as _av
import its.dashboard.components.incident_view as _iv
import its.dashboard.components.security_view as _sv
import its.dashboard.components.traffic_view as _tv
import its.dashboard.styles.theme as _th

# Ensure long-running Streamlit processes always execute latest component code
importlib.reload(_av)
importlib.reload(_iv)
importlib.reload(_sv)
importlib.reload(_tv)
importlib.reload(_th)

from its.dashboard.components.assistant_view import render_assistant_view
from its.dashboard.components.incident_view import render_incident_view
from its.dashboard.components.security_view import render_security_view
from its.dashboard.components.traffic_view import render_traffic_view
from its.dashboard.services.its_dashboard_service import ITSDashboardService
from its.dashboard.styles.theme import (
    apply_custom_styles,
    render_simulation_banner,
)


@st.cache_resource
def get_dashboard_service() -> ITSDashboardService:
    """Instantiates and caches the singleton ITSDashboardService."""
    return ITSDashboardService()


def render_sidebar(service: ITSDashboardService) -> None:
    """Renders the dashboard sidebar containing system status and controls."""
    with st.sidebar:
        st.markdown("### 🎛️ SOC System Status")

        # Simulation Mode Indicator
        st.markdown(
            """
            <div style="background: rgba(3, 105, 161, 0.2); border: 1px solid #0284c7; border-radius: 6px; padding: 10px; margin-bottom: 12px;">
                <div style="color: #38bdf8; font-weight: 700; font-size: 0.85rem;">OPERATIONAL ENVIRONMENT</div>
                <div style="color: #f0f9ff; font-size: 0.95rem; font-weight: 600;">SIMULATION MODE</div>
                <div style="color: #94a3b8; font-size: 0.75rem; margin-top: 4px;">Simulated telemetry dataset (roads, traffic, incidents). No direct actuator connections.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("---")
        st.markdown("#### 🔒 Security Architecture")
        st.write("**Middleware:** Frozen 8-Stage Pipeline")
        st.write("**Detector:** ITSTransportationThreatDetector")
        st.write("**Domain Demarcation:** Enclosed Context Envelopes")

        db_connected = service.is_db_connected
        if db_connected:
            st.success("🟢 PostgreSQL Audit: Active")
        else:
            st.warning("🟠 PostgreSQL Audit: Offline (In-Memory Session Mode)")

        st.markdown("---")
        st.markdown("#### 📊 Domain Telemetry Summary")
        kpis = service.get_network_kpis()
        st.write(f"- **Simulated Roads:** {kpis['total_roads']}")
        st.write(f"- **Monitored Segments:** {kpis['monitored_segments']}")
        st.write(f"- **Active Incidents:** {kpis['active_incidents']}")
        st.write(f"- **Critical Congestion:** {kpis['critical_congestion_count']}")

        st.markdown("---")
        st.caption(
            "Academic Research Prototype: Secure Large Language Model-Based Intelligent "
            "Transportation Management System."
        )


def main() -> None:
    """Main execution function for the ITS Dashboard."""
    st.set_page_config(
        page_title="ITS Security Operations Center | AI-SecOps",
        page_icon="🚦",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply cyber-transportation styling
    apply_custom_styles()

    # Prominent Simulation Mode Banner
    render_simulation_banner()

    # Top Header
    st.markdown(
        """
        <div class="soc-header">
            <div class="soc-title-group">
                <h1>🚦 Intelligent Transportation System — SOC</h1>
                <div class="soc-subtitle">
                    Real-Time Simulated Telemetry Monitoring &amp; AI-SecOps Security Middleware Integration
                </div>
            </div>
            <div style="text-align: right;">
                <span class="sim-mode-badge">SIMULATION MODE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Initialize Backend Service
    service = get_dashboard_service()

    # Sidebar
    render_sidebar(service)

    # Main Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🚦 Traffic Network Overview",
        "⚠️ Incident Monitoring",
        "🤖 AI Transportation Assistant",
        "🛡️ Security Telemetry & Audit",
    ])

    with tab1:
        render_traffic_view(service)

    with tab2:
        render_incident_view(service)

    with tab3:
        render_assistant_view(service)

    with tab4:
        render_security_view(service)


if __name__ == "__main__":
    main()
