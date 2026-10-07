"""
ITS Dashboard Theme and Visual Styling.

Provides unified cyber-transportation styling, CSS rules, KPI card renderers,
and simulation mode indicators for the Intelligent Transportation System SOC dashboard.
"""

from __future__ import annotations

import streamlit as st


def apply_custom_styles() -> None:
    """Injects custom CSS for cyber-transportation SOC aesthetic."""
    st.markdown(
        """
        <style>
        /* Base Dark Theme Adjustments */
        .main .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
            max-width: 95%;
        }

        /* Header & Navigation Styling */
        .soc-header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 18px 24px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .soc-title-group h1 {
            color: #38bdf8;
            font-size: 1.8rem;
            font-weight: 700;
            margin: 0;
            letter-spacing: -0.5px;
        }

        .soc-subtitle {
            color: #94a3b8;
            font-size: 0.9rem;
            margin-top: 4px;
        }

        /* Simulation Mode Badge */
        .sim-mode-badge {
            background-color: #0369a1;
            color: #f0f9ff;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 9999px;
            border: 1px solid #38bdf8;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Status & Security Badges */
        .badge-allowed {
            background-color: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid #10b981;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }

        .badge-blocked {
            background-color: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid #ef4444;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }

        .badge-warning {
            background-color: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid #f59e0b;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }

        .badge-info {
            background-color: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            border: 1px solid #0284c7;
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            display: inline-block;
        }

        /* Glassmorphism Metric / KPI Cards */
        .kpi-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 16px 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
            transition: transform 0.15s ease-in-out, border-color 0.15s ease-in-out;
        }
        .kpi-card:hover {
            border-color: #38bdf8;
        }

        .kpi-label {
            color: #94a3b8;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }

        .kpi-value {
            color: #f8fafc;
            font-size: 1.6rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .kpi-subtext {
            color: #64748b;
            font-size: 0.75rem;
            margin-top: 6px;
        }

        /* Stage Pipeline Flow */
        .stage-box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 10px 14px;
            text-align: center;
            font-size: 0.8rem;
            color: #cbd5e1;
        }
        .stage-box.passed {
            border-color: #10b981;
            color: #34d399;
        }
        .stage-box.blocked {
            border-color: #ef4444;
            color: #f87171;
            background: rgba(239, 68, 68, 0.1);
        }
        .stage-box.skipped {
            border-color: #475569;
            color: #64748b;
        }

        /* Security Alert Box */
        .sec-alert-box {
            background: rgba(239, 68, 68, 0.08);
            border-left: 4px solid #ef4444;
            border-radius: 4px;
            padding: 12px 16px;
            margin: 10px 0;
            color: #fca5a5;
            font-size: 0.9rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_simulation_banner() -> None:
    """Renders prominent simulation environment indicator."""
    st.markdown(
        """
        <div style="background: rgba(3, 105, 161, 0.15); border: 1px solid #0284c7; border-radius: 8px; padding: 8px 16px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 1.1rem;">🧪</span>
                <span style="color: #38bdf8; font-weight: 600; font-size: 0.85rem;">SIMULATION MODE</span>
                <span style="color: #94a3b8; font-size: 0.82rem;">— Operating on simulated ITS telemetry datasets (roads, traffic conditions, incidents). Zero direct external actuation.</span>
            </div>
            <span class="sim-mode-badge">SIMULATED ENVIRONMENT</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_badge(text: str, badge_type: str = "info") -> str:
    """
    Returns HTML markup for a styled status badge.

    Args:
        text: Badge label.
        badge_type: One of 'allowed', 'blocked', 'warning', 'info'.
    """
    css_class = f"badge-{badge_type}"
    return f'<span class="{css_class}">{text}</span>'


def render_kpi_card(
    label: str,
    value: str | int | float,
    subtext: str = "",
    icon: str = "",
) -> None:
    """
    Renders a glassmorphism KPI summary card.

    Args:
        label: Metric title.
        value: Primary metric value.
        subtext: Secondary helper text.
        icon: Optional leading emoji or icon.
    """
    display_label = f"{icon} {label}".strip() if icon else label
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">{display_label}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-subtext">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
