"""
Centralized Immutable Constants for the Risk Engine — Sprint 7.

Serves as the single source of truth for all default thresholds, feature weight
distributions, confidence floors, score precision limits, telemetry budgets, and
general system defaults used across the Risk Engine submodules.

Design Principles:
    - SOLID: Single responsibility for central constant management.
    - DRY: Centralized values eliminating magic numbers throughout the framework.
    - Immutability: Pure module-level constants (primitives and tuples) ensuring thread safety.
    - OWASP Secure-by-Design: Fail-secure defaults and strict upper execution bounds.
"""

from __future__ import annotations

# ===========================================================================
# 1. Risk Threshold Defaults (Normalized Range [0.0, 1.0])
# ===========================================================================

#: Upper score boundary threshold for LOW risk classification tier.
DEFAULT_LOW_THRESHOLD: float = 0.30

#: Upper score boundary threshold for MEDIUM risk classification tier.
DEFAULT_MEDIUM_THRESHOLD: float = 0.60

#: Upper score boundary threshold for HIGH risk classification tier.
DEFAULT_HIGH_THRESHOLD: float = 0.85

#: Ceiling score boundary threshold for CRITICAL risk classification tier.
DEFAULT_CRITICAL_THRESHOLD: float = 1.00


# ===========================================================================
# 2. Default Component Feature Weights (Sum = 1.0)
# ===========================================================================

#: Default weight assigned to Prompt Firewall security scan findings.
DEFAULT_PROMPT_FIREWALL_WEIGHT: float = 0.55

#: Default weight assigned to Input Validator structural anomaly findings.
DEFAULT_INPUT_VALIDATOR_WEIGHT: float = 0.25

#: Default weight assigned to historical user/session threat baseline.
DEFAULT_HISTORICAL_WEIGHT: float = 0.10

#: Default weight assigned to custom contextual request metadata features.
DEFAULT_CUSTOM_WEIGHT: float = 0.10


# ===========================================================================
# 3. Confidence Metrics Defaults
# ===========================================================================

#: Absolute minimum confidence boundary floor.
MIN_CONFIDENCE: float = 0.0

#: Absolute maximum confidence boundary ceiling.
MAX_CONFIDENCE: float = 1.0

#: Default baseline confidence rating when detector signals are uncalibrated.
DEFAULT_CONFIDENCE: float = 1.0

#: Default weight assigned to historical precision in confidence calculations.
DEFAULT_HISTORICAL_CONFIDENCE_WEIGHT: float = 0.20

#: Default weight assigned to raw detector signal confidence.
DEFAULT_DETECTOR_CONFIDENCE_WEIGHT: float = 0.50

#: Default weight assigned to validator structural compliance confidence.
DEFAULT_VALIDATOR_CONFIDENCE_WEIGHT: float = 0.30


# ===========================================================================
# 4. Score Normalization & Numerical Precision
# ===========================================================================

#: Minimum bounds for normalized composite scores.
MIN_NORMALIZED_SCORE: float = 0.0

#: Maximum bounds for normalized composite scores.
MAX_NORMALIZED_SCORE: float = 1.0

#: Decimal place rounding precision for floating-point risk scores.
DEFAULT_SCORE_PRECISION: int = 4

#: Floating-point tolerance threshold for equality and sum-to-1 validations.
FLOAT_COMPARISON_TOLERANCE: float = 1e-5


# ===========================================================================
# 5. Telemetry, Limits & Performance Budgets
# ===========================================================================

#: Decimal precision for execution timing telemetry (milliseconds).
DEFAULT_EXECUTION_PRECISION: int = 2

#: Maximum number of entries allowed in metadata dictionaries.
DEFAULT_METADATA_LIMIT: int = 100

#: Maximum number of evidence items retained per assessment audit log.
DEFAULT_EVIDENCE_LIMIT: int = 500

#: Maximum targeted execution duration budget for risk evaluation (ms).
DEFAULT_LATENCY_BUDGET_MS: float = 2.0


# ===========================================================================
# 6. Non-Linear Amplification & Compound Threat Factors
# ===========================================================================

#: Multi-hit diminishing sum amplification coefficient (alpha).
DEFAULT_AMPLIFICATION_ALPHA: float = 0.15

#: Compound multi-module threat interaction multiplier coefficient (gamma).
DEFAULT_COMPOUND_GAMMA: float = 0.25


# ===========================================================================
# 7. General System & Pipeline Defaults
# ===========================================================================

#: Default system timezone designation for assessment timestamps.
DEFAULT_TIMEZONE: str = "UTC"

#: Default text encoding format.
DEFAULT_ENCODING: str = "utf-8"

#: Default system fallback fail-safe mode on unhandled internal error.
DEFAULT_FAIL_SAFE_MODE: str = "FAIL_SECURE"

#: Default risk scoring strategy identifier.
DEFAULT_SCORING_STRATEGY: str = "COMPOSITE"

#: Default multi-module finding aggregation strategy identifier.
DEFAULT_AGGREGATION_STRATEGY: str = "MAX_SCORE"
