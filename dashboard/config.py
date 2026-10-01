"""
Dashboard Configuration & Theme Definitions for AI-SecOps Streamlit UI.
"""

PAGE_TITLE = "AISECOPS"
PAGE_ICON = "🛡️"
PAGE_LAYOUT = "wide"

# UI Color Palette
COLOR_SUCCESS = "#10B981"
COLOR_DANGER = "#EF4444"
COLOR_WARNING = "#F59E0B"
COLOR_INFO = "#3B82F6"
COLOR_NEUTRAL = "#6B7280"
COLOR_DARK_BG = "#0E1117"
COLOR_CARD_BG = "#1A1D24"

# Pipeline Stage Order for Lifecycle Visualization
PIPELINE_STAGES = [
    "InputValidator",
    "PromptBuilder",
    "PromptFirewall",
    "RiskEngine",
    "PolicyEngine",
    "PromptHardener",
    "LLMProvider",
    "OutputGuard",
]

DEFAULT_REFRESH_INTERVAL_SEC = 10
DEFAULT_ROW_LIMIT = 50
