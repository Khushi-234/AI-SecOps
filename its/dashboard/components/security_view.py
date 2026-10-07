"""
Security View Component for ITS Dashboard.

Visualizes AI-SecOps 8-stage pipeline enforcement, ITS threat detection categories,
and security audit logs from PostgreSQL (with non-blocking in-memory fallback).
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from its.dashboard.services.its_dashboard_service import ITSDashboardService
from its.dashboard.styles.theme import render_badge, render_kpi_card


PIPELINE_STAGES = [
    ("Stage 1", "InputValidator", "Syntactic schema & payload length verification"),
    ("Stage 2", "PromptBuilder", "ITS domain context & security system prompt construction"),
    ("Stage 3", "PromptFirewall", "Detector execution (including ITSTransportationThreatDetector)"),
    ("Stage 4", "RiskEngine", "Composite risk calculation & threshold evaluation"),
    ("Stage 5", "PolicyEngine", "Deterministic Allow / Block security policy decision"),
    ("Stage 6", "PromptHardener", "Instruction boundary defense & anti-leakage injection"),
    ("Stage 7", "LLMProvider", "Execution against configured LLM model (Skipped on Block)"),
    ("Stage 8", "OutputGuard", "Post-generation verification & credential masking"),
]

ITS_THREAT_CATEGORIES = [
    ("ITS_SIGNAL_OVERRIDE", "Signal Manipulation", "Attempting unauthorized phase/timing modifications on traffic lights"),
    ("ITS_ACTUATION_TAMPERING", "Actuator Tampering", "Attempting unauthorized variable speed limit, lane control, or gate actuation"),
    ("ITS_EMERGENCY_MANIPULATION", "Emergency Impersonation", "Fabricating emergency convoys, clearing corridors, or spoofing preemption"),
    ("ITS_PRIORITY_ABUSE", "Priority Transit Abuse", "Falsifying transit prioritization or fleet dispatch authorization"),
    ("ITS_MALICIOUS_ROUTING", "Malicious Traffic Routing", "Inducing artificial congestion or diverting vehicles into closed hazards"),
    ("ITS_SCADA_EXPLOITATION", "SCADA Exploitation", "Accessing engineering shells, PLC protocols, or controller firmware passwords"),
    ("ITS_SENSOR_SPOOFING", "Sensor Spoofing", "Injecting false speed/occupancy loops or fabricating congestion data"),
    ("ITS_TELEMETRY_INJECTION", "Telemetry Injection", "Injecting delimiter breaks or instructions into telemetry fields"),
]


def render_security_view(service: ITSDashboardService) -> None:
    """
    Renders the Security Telemetry & Audit tab.

    Args:
        service: Initialized ITSDashboardService instance.
    """
    st.markdown("### 🛡️ AI-SecOps Security Telemetry & Audit")
    st.caption("Monitoring middleware defense stages, transportation threat detection, and non-blocking PostgreSQL audit records.")

    # Top Security KPIs
    kpis = service.get_security_kpis()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_kpi_card("Total Monitored Queries", kpis["total_requests"], "Processed through pipeline", "🛡️")
    with c2:
        render_kpi_card("Allowed Requests", kpis["allowed_requests"], "Passed all defense checks", "✅")
    with c3:
        render_kpi_card("Blocked Threats", kpis["blocked_requests"], "Intercepted & neutralized", "🚫")
    with c4:
        db_icon = "🟢" if "Online" in kpis["db_status"] else "🟠"
        render_kpi_card("Audit Storage Status", kpis["db_status"], "Audit persistence backend", db_icon)

    st.markdown("---")

    # Pipeline Stage Architecture
    st.markdown("#### ⚙️ Frozen 8-Stage Security Pipeline Architecture")
    st.caption("All ITS transportation queries pass strictly through this sequence without exception.")

    pipeline_cols = st.columns(4)
    for idx, (stg_num, stg_name, desc) in enumerate(PIPELINE_STAGES):
        col_target = pipeline_cols[idx % 4]
        with col_target:
            st.markdown(
                f"""
                <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 10px; min-height: 120px;">
                    <div style="font-size: 0.75rem; color: #38bdf8; font-weight: 700;">{stg_num}</div>
                    <div style="font-size: 0.95rem; font-weight: 700; color: #f8fafc; margin-top: 2px;">{stg_name}</div>
                    <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 6px; line-height: 1.3;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("---")

    # Transportation Threat Taxonomy
    st.markdown("#### 🚨 Transportation Domain Threat Detection Rules")
    st.caption("Active detectors enforced by `ITSTransportationThreatDetector` within `PromptFirewall`.")

    threat_rows = [
        {"Rule Code": code, "Category": cat, "Detection Scope": scope}
        for code, cat, scope in ITS_THREAT_CATEGORIES
    ]
    st.dataframe(pd.DataFrame(threat_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # Audit Events Table
    st.markdown("#### 📜 Security Audit Event Log")
    db_conn = service.is_db_connected
    if db_conn:
        st.success("🟢 PostgreSQL Audit Database Connected — Querying persistent audit log table (`audit_events`).")
    else:
        st.info("🟠 PostgreSQL Audit Database Offline — Displaying in-memory active session telemetry log.")

    events = service.get_audit_telemetry(limit=50)
    if events:
        audit_df = pd.DataFrame(events)
        st.dataframe(
            audit_df[
                ["timestamp", "status", "action", "severity", "component", "message", "source"]
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No audit events recorded yet in the current session.")
