"""
Unit tests for risk_engine.confidence — Sprint 7 Verification Phase.

Tests all public behavior of ConfidenceCalculator:
    - Evidence input validation (empty collection, invalid items, non-sequences)
    - Single and multi-item confidence evaluation
    - High and low confidence scenarios
    - Dedicated calculation strategies (WEIGHTED, CONSENSUS, HISTORICAL, HYBRID)
    - String strategy resolution ("WEIGHTED", "CONSENSUS", "HISTORICAL", "HYBRID")
    - Boundary metric handling (0.0 floor, 1.0 ceiling, precision rounding)
    - Historical precision parameter overrides
    - Deterministic output repeatability with fixed timestamps
    - Fail-secure error propagation (InvalidRiskInputError, ConfidenceCalculationError)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from risk_engine.confidence import ConfidenceCalculator
from risk_engine.enums import ConfidenceStrategy
from risk_engine.exceptions import ConfidenceCalculationError, InvalidRiskInputError
from risk_engine.models import RiskEvidence

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def calculator() -> ConfidenceCalculator:
    """Provide a default ConfidenceCalculator instance."""
    return ConfidenceCalculator()


@pytest.fixture
def sample_evidence_list() -> list[RiskEvidence]:
    """Provide a list of valid, diverse RiskEvidence items with deterministic timestamps."""
    return [
        RiskEvidence(
            evidence_id="ev-1",
            source_module="PROMPT_FIREWALL",
            detector_name="JailbreakDetector",
            finding_type="JAILBREAK",
            severity="CRITICAL",
            confidence=0.95,
            risk_score=0.90,
            description="High confidence jailbreak pattern",
            timestamp=FIXED_TIMESTAMP,
        ),
        RiskEvidence(
            evidence_id="ev-2",
            source_module="INPUT_VALIDATOR",
            detector_name="LengthValidator",
            finding_type="LENGTH_EXCEEDED",
            severity="HIGH",
            confidence=0.85,
            risk_score=0.70,
            description="Medium-high confidence length validation error",
            timestamp=FIXED_TIMESTAMP,
        ),
    ]


# =============================================================================
# 1. Empty & Null Input Validation Tests
# =============================================================================


def test_calculate_empty_evidence_raises_invalid_input(calculator: ConfidenceCalculator):
    """Verify calling calculate() with an empty sequence raises InvalidRiskInputError or ConfidenceCalculationError."""
    # Arrange & Act & Assert
    with pytest.raises((InvalidRiskInputError, ConfidenceCalculationError)) as exc_info:
        calculator.calculate([])
    assert exc_info.value is not None


def test_calculate_none_evidence_raises_invalid_input(calculator: ConfidenceCalculator):
    """Verify calling calculate() with None raises InvalidRiskInputError or ConfidenceCalculationError."""
    # Arrange & Act & Assert
    with pytest.raises((InvalidRiskInputError, ConfidenceCalculationError)) as exc_info:
        calculator.calculate(None)  # type: ignore[arg-type]
    assert exc_info.value is not None


def test_calculate_non_sequence_raises_invalid_input(calculator: ConfidenceCalculator):
    """Verify passing a non-sequence object raises InvalidRiskInputError, ConfidenceCalculationError, or TypeError."""
    # Arrange & Act & Assert
    with pytest.raises((InvalidRiskInputError, ConfidenceCalculationError, TypeError)) as exc_info:
        calculator.calculate(12345)  # type: ignore[arg-type]
    assert exc_info.value is not None



# =============================================================================
# 2. Single & Multi-Item Calculation Tests
# =============================================================================


def test_calculate_single_evidence_item(calculator: ConfidenceCalculator):
    """Verify calculating confidence for a single evidence item returns a valid bounded float."""
    # Arrange
    item = RiskEvidence(
        evidence_id="ev-single",
        source_module="PROMPT_FIREWALL",
        detector_name="SingleDetector",
        finding_type="SINGLE_FINDING",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.50,
        description="Single item test",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    score = calculator.calculate([item])

    # Assert
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_calculate_multiple_evidence_items(
    calculator: ConfidenceCalculator, sample_evidence_list: list[RiskEvidence]
):
    """Verify calculating confidence for multiple evidence items returns a composite confidence rating."""
    # Act
    score = calculator.calculate(sample_evidence_list)

    # Assert
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_calculate_low_confidence_scenario(calculator: ConfidenceCalculator):
    """Verify evidence items with low upstream confidence yield a low overall confidence rating."""
    # Arrange
    low_evidence = [
        RiskEvidence(
            evidence_id="ev-low-1",
            source_module="INPUT_VALIDATOR",
            detector_name="LowDet1",
            finding_type="TYPE_1",
            severity="LOW",
            confidence=0.10,
            risk_score=0.20,
            description="Low confidence finding 1",
            timestamp=FIXED_TIMESTAMP,
        ),
        RiskEvidence(
            evidence_id="ev-low-2",
            source_module="INPUT_VALIDATOR",
            detector_name="LowDet2",
            finding_type="TYPE_2",
            severity="LOW",
            confidence=0.20,
            risk_score=0.15,
            description="Low confidence finding 2",
            timestamp=FIXED_TIMESTAMP,
        ),
    ]

    # Act
    score = calculator.calculate(low_evidence)

    # Assert
    assert 0.0 <= score <= 0.60


def test_calculate_high_confidence_scenario(calculator: ConfidenceCalculator):
    """Verify evidence items with high upstream confidence yield a high overall confidence rating."""
    # Arrange
    high_evidence = [
        RiskEvidence(
            evidence_id="ev-high-1",
            source_module="PROMPT_FIREWALL",
            detector_name="HighDet1",
            finding_type="TYPE_1",
            severity="CRITICAL",
            confidence=0.98,
            risk_score=0.95,
            description="High confidence finding 1",
            timestamp=FIXED_TIMESTAMP,
        ),
        RiskEvidence(
            evidence_id="ev-high-2",
            source_module="PROMPT_FIREWALL",
            detector_name="HighDet2",
            finding_type="TYPE_2",
            severity="CRITICAL",
            confidence=0.95,
            risk_score=0.90,
            description="High confidence finding 2",
            timestamp=FIXED_TIMESTAMP,
        ),
    ]

    # Act
    score = calculator.calculate(high_evidence)

    # Assert
    assert score >= 0.80


# =============================================================================
# 3. Strategy Variant Tests
# =============================================================================


@pytest.mark.parametrize(
    "strategy",
    [
        ConfidenceStrategy.WEIGHTED,
        ConfidenceStrategy.CONSENSUS,
        ConfidenceStrategy.HISTORICAL,
        ConfidenceStrategy.HYBRID,
    ],
)
def test_calculate_all_enum_strategies(
    calculator: ConfidenceCalculator,
    sample_evidence_list: list[RiskEvidence],
    strategy: ConfidenceStrategy,
):
    """Verify all ConfidenceStrategy enum options calculate valid scores."""
    # Act
    score = calculator.calculate(sample_evidence_list, strategy=strategy)

    # Assert
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


@pytest.mark.parametrize(
    "strategy_str",
    ["WEIGHTED", "CONSENSUS", "HISTORICAL", "HYBRID"],
)
def test_calculate_string_strategy_resolution(
    calculator: ConfidenceCalculator,
    sample_evidence_list: list[RiskEvidence],
    strategy_str: str,
):
    """Verify strategy names passed as uppercase string designations resolve correctly."""
    # Act
    score = calculator.calculate(sample_evidence_list, strategy=strategy_str)

    # Assert
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


# =============================================================================
# 4. Boundary Values, Precision, and Parameters
# =============================================================================


def test_calculate_min_confidence_boundary(calculator: ConfidenceCalculator):
    """Verify evidence with 0.0 confidence returns a result bounded at or above 0.0."""
    # Arrange
    min_evidence = [
        RiskEvidence(
            evidence_id="ev-min",
            source_module="INPUT_VALIDATOR",
            detector_name="ZeroDet",
            finding_type="ZERO",
            severity="INFO",
            confidence=0.0,
            risk_score=0.0,
            description="Min confidence item",
            timestamp=FIXED_TIMESTAMP,
        )
    ]

    # Act
    score = calculator.calculate(min_evidence)

    # Assert
    assert score >= 0.0


def test_calculate_max_confidence_boundary(calculator: ConfidenceCalculator):
    """Verify evidence with 1.0 confidence returns a result bounded at or below 1.0."""
    # Arrange
    max_evidence = [
        RiskEvidence(
            evidence_id="ev-max",
            source_module="PROMPT_FIREWALL",
            detector_name="MaxDet",
            finding_type="MAX",
            severity="CRITICAL",
            confidence=1.0,
            risk_score=1.0,
            description="Max confidence item",
            timestamp=FIXED_TIMESTAMP,
        )
    ]

    # Act
    score = calculator.calculate(max_evidence)

    # Assert
    assert score <= 1.0


def test_calculate_historical_precision_override(
    calculator: ConfidenceCalculator, sample_evidence_list: list[RiskEvidence]
):
    """Verify historical_precision parameter modifies historical and hybrid strategy outputs."""
    # Act
    score_default = calculator.calculate(
        sample_evidence_list, strategy=ConfidenceStrategy.HISTORICAL, historical_precision=0.50
    )
    score_high = calculator.calculate(
        sample_evidence_list, strategy=ConfidenceStrategy.HISTORICAL, historical_precision=0.99
    )

    # Assert
    assert score_high > score_default


def test_calculate_output_rounding_precision(
    calculator: ConfidenceCalculator, sample_evidence_list: list[RiskEvidence]
):
    """Verify calculated confidence rating adheres to 4-decimal place precision."""
    # Act
    score = calculator.calculate(sample_evidence_list)

    # Assert: decimal digits beyond 4 places must be zero
    assert round(score, 4) == score


# =============================================================================
# 5. Negative & Fail-Secure Tests
# =============================================================================


def test_calculate_invalid_item_type_in_sequence_raises_invalid_input(
    calculator: ConfidenceCalculator,
):
    """Verify a sequence containing non-RiskEvidence elements raises InvalidRiskInputError or ConfidenceCalculationError."""
    # Arrange
    invalid_sequence = ["not_an_evidence_object"]

    # Act & Assert
    with pytest.raises((InvalidRiskInputError, ConfidenceCalculationError)) as exc_info:
        calculator.calculate(invalid_sequence)  # type: ignore[arg-type]
    assert exc_info.value is not None


def test_calculate_invalid_strategy_string_raises_confidence_error(
    calculator: ConfidenceCalculator, sample_evidence_list: list[RiskEvidence]
):
    """Verify an unrecognized strategy string raises ConfidenceCalculationError."""
    # Act & Assert
    with pytest.raises((ConfidenceCalculationError, InvalidRiskInputError, ValueError)) as exc_info:
        calculator.calculate(sample_evidence_list, strategy="INVALID_STRATEGY")
    assert exc_info.value is not None


# =============================================================================
# 6. Deterministic Output Repeatability Tests
# =============================================================================


def test_calculate_deterministic_repeatability(
    calculator: ConfidenceCalculator, sample_evidence_list: list[RiskEvidence]
):
    """Verify calling calculate() multiple times with identical inputs returns identical float values."""
    # Act
    res1 = calculator.calculate(sample_evidence_list, strategy=ConfidenceStrategy.WEIGHTED)
    res2 = calculator.calculate(sample_evidence_list, strategy=ConfidenceStrategy.WEIGHTED)

    # Assert
    assert res1 == res2
