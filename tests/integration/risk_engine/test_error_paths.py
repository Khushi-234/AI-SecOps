"""
Error Path Integration tests for the AI-SecOps Risk Engine — Sprint 7 Phase 6.

Verifies fail-secure behavior, input validation, and domain exception propagation across
the production Risk Engine pipeline (RiskEngineFacade, RiskEngine, RiskAggregator,
CompositeScorer, ConfidenceCalculator, PolicyMapper).

Scenarios Covered:
    - Empty input payload validation (InvalidRiskInputError)
    - None input payload handling (InvalidRiskInputError)
    - Invalid evidence object types (int, float, invalid strings) (RiskEngineError / RiskAggregationError)
    - Malformed RiskEvidence boundary constraints (RiskValidationError for out-of-range risk_score or confidence)
    - Unsupported merge strategy (RiskAggregationError)
    - Mixed valid and invalid evidence collections (RiskEngineError / RiskAggregationError)
    - Response facade exception propagation (evaluate_response)
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from risk_engine.exceptions import (
    InvalidRiskInputError,
    RiskAggregationError,
    RiskEngineError,
    RiskValidationError,
)
from risk_engine.models import RiskEvidence
from risk_engine.risk_engine import RiskEngineFacade, get_risk_engine

#: Deterministic UTC timestamp for error path integration test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def engine() -> RiskEngineFacade:
    """Provide a real, fully wired RiskEngineFacade instance using production components."""
    return get_risk_engine()


@pytest.fixture
def valid_evidence() -> RiskEvidence:
    """Provide a canonical valid RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-valid-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Canonical valid test evidence item",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Null & Empty Payload Validation Tests
# =============================================================================


def test_error_path_empty_input_sources_raises_invalid_input(engine: RiskEngineFacade):
    """Verify calling evaluate() with no sources raises InvalidRiskInputError with field attribution."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate()
    assert exc_info.value.details.get("field") == "sources"


def test_error_path_none_input_source_raises_invalid_input(engine: RiskEngineFacade):
    """Verify passing None as input source raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate(None)
    assert "sources" in str(exc_info.value.details.get("field", ""))


# =============================================================================
# 2. Invalid Payload Type Validation Tests
# =============================================================================


@pytest.mark.parametrize(
    "invalid_payload",
    [
        12345,
        3.14159,
        "raw_unstructured_string_payload",
    ],
)
def test_error_path_invalid_object_type_raises_risk_engine_error(
    engine: RiskEngineFacade, invalid_payload: object
):
    """Verify passing unsupported payload types raises RiskEngineError / RiskAggregationError."""
    # Act & Assert
    with pytest.raises(RiskEngineError) as exc_info:
        engine.evaluate(invalid_payload)
    assert isinstance(exc_info.value, RiskEngineError)



# =============================================================================
# 3. Model Boundary & Schema Validation Tests
# =============================================================================


@pytest.mark.parametrize("bad_score", [-0.1, 1.1, 2.5, -5.0])
def test_error_path_invalid_risk_score_range_raises_validation_error(bad_score: float):
    """Verify instantiating RiskEvidence with risk_score outside [0.0, 1.0] raises RiskValidationError."""
    # Act & Assert
    with pytest.raises(RiskValidationError):
        RiskEvidence(
            evidence_id="ev-bad-score",
            source_module="PROMPT_FIREWALL",
            detector_name="JailbreakDetector",
            finding_type="JAILBREAK",
            severity="HIGH",
            confidence=0.90,
            risk_score=bad_score,
            description="Out of bounds score test",
            timestamp=FIXED_TIMESTAMP,
        )


@pytest.mark.parametrize("bad_confidence", [-0.1, 1.1, 2.5, -1.0])
def test_error_path_invalid_confidence_range_raises_validation_error(bad_confidence: float):
    """Verify instantiating RiskEvidence with confidence outside [0.0, 1.0] raises RiskValidationError."""
    # Act & Assert
    with pytest.raises(RiskValidationError):
        RiskEvidence(
            evidence_id="ev-bad-conf",
            source_module="PROMPT_FIREWALL",
            detector_name="JailbreakDetector",
            finding_type="JAILBREAK",
            severity="HIGH",
            confidence=bad_confidence,
            risk_score=0.50,
            description="Out of bounds confidence test",
            timestamp=FIXED_TIMESTAMP,
        )


# =============================================================================
# 4. Strategy & Merge Error Path Tests
# =============================================================================


def test_error_path_unsupported_merge_strategy_raises_aggregation_error(
    engine: RiskEngineFacade, valid_evidence: RiskEvidence
):
    """Verify requesting an unrecognized merge_strategy string raises RiskAggregationError."""
    # Act & Assert
    with pytest.raises(RiskAggregationError):
        engine.evaluate(valid_evidence, merge_strategy="NON_EXISTENT_MERGE_STRATEGY")


# =============================================================================
# 5. Corrupted & Mixed Evidence Collection Tests
# =============================================================================


def test_error_path_mixed_valid_and_invalid_evidence_fails_securely(
    engine: RiskEngineFacade, valid_evidence: RiskEvidence
):
    """Verify evaluating a collection containing both valid and invalid items fails securely without partial execution."""
    # Arrange
    invalid_item = "corrupted_unsupported_item_string"

    # Act & Assert: pipeline must fail securely with domain exception
    with pytest.raises(RiskEngineError):
        engine.evaluate(valid_evidence, invalid_item)


# =============================================================================
# 6. Response Facade Error Path Propagation Tests
# =============================================================================


def test_error_path_evaluate_response_empty_sources_raises_invalid_input(engine: RiskEngineFacade):
    """Verify evaluate_response() with empty sources raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate_response()
    assert exc_info.value.details.get("field") == "sources"


def test_error_path_evaluate_response_invalid_payload_raises_risk_engine_error(engine: RiskEngineFacade):
    """Verify evaluate_response() with invalid payload types raises RiskEngineError."""
    # Act & Assert
    with pytest.raises(RiskEngineError):
        engine.evaluate_response(99999)
