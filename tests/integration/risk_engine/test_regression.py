"""
Regression Integration tests for the AI-SecOps Risk Engine — Sprint 7 Phase 6.

Provides regression protection ensuring previously verified Risk Engine contract behavior
remains stable as future changes, optimizations, or strategy extensions are introduced:
    - Stable evaluation of canonical single and multi-source evidence
    - Stable RiskLevel classification and RecommendedAction generation
    - Stable score and confidence range bounds [0.0, 1.0]
    - Stable RiskEngineResponse gateway DTO container structure
    - Stable duplicate evidence handling and ordering invariance
    - Stable unknown detector and mixed module handling
    - Regression protection for minimum (0.0) and maximum (1.0) boundary conditions
    - Regression protection for fail-secure domain exception behavior
    - Regression protection for multi-instance repeated execution stability
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import InvalidRiskInputError, RiskEngineError
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
    RiskRecommendation,
)
from risk_engine.risk_engine import RiskEngineFacade, get_risk_engine

#: Deterministic UTC timestamp for regression integration test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def engine() -> RiskEngineFacade:
    """Provide a real, fully wired RiskEngineFacade instance using production components."""
    return get_risk_engine()


@pytest.fixture
def canonical_evidence() -> RiskEvidence:
    """Provide a canonical single RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-regr-canon-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.75,
        description="Canonical regression evidence item",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Canonical Evidence & Contract Stability Regression Tests
# =============================================================================


def test_regression_canonical_single_evidence_contract_stability(
    engine: RiskEngineFacade, canonical_evidence: RiskEvidence
):
    """Regression test: Single canonical evidence evaluation maintains stable public assessment DTO contract."""
    # Act
    assessment = engine.evaluate(canonical_evidence)

    # Assert contract stability
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0
    assert isinstance(assessment.risk_level, RiskLevel)
    assert isinstance(assessment.recommended_action, RecommendedAction)
    assert len(assessment.evidence) == 1


def test_regression_canonical_multi_evidence_contract_stability(engine: RiskEngineFacade):
    """Regression test: Multi-source evidence evaluation maintains stable public assessment DTO contract."""
    # Arrange
    ev1 = RiskEvidence("ev-reg-m1", "PROMPT_FIREWALL", "JailbreakDetector", "JAILBREAK", "HIGH", 0.90, 0.80, "F1", timestamp=FIXED_TIMESTAMP)
    ev2 = RiskEvidence("ev-reg-m2", "INPUT_VALIDATOR", "LengthValidator", "LENGTH_EXCEEDED", "MEDIUM", 0.80, 0.40, "F2", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(ev1, ev2)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert len(assessment.evidence) == 2
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0


# =============================================================================
# 2. Boundary Condition Regression Tests
# =============================================================================


def test_regression_minimum_score_boundary_stability(engine: RiskEngineFacade):
    """Regression test: Evaluating zero risk score evidence yields stable valid DTO in range [0.0, 1.0]."""
    # Arrange
    ev_zero = RiskEvidence("ev-zero", "PROMPT_FIREWALL", "JailbreakDetector", "JAILBREAK", "LOW", 1.0, 0.0, "Zero score", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(ev_zero)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.recommended_action == RecommendedAction.ALLOW


def test_regression_maximum_score_boundary_stability(engine: RiskEngineFacade):
    """Regression test: Evaluating maximum risk score (1.0) evidence yields stable CRITICAL assessment."""
    # Arrange
    ev_max = RiskEvidence("ev-max", "PROMPT_FIREWALL", "JailbreakDetector", "JAILBREAK", "CRITICAL", 1.0, 1.0, "Max score", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(ev_max)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.recommended_action == RecommendedAction.BLOCK


# =============================================================================
# 3. Gateway Container DTO Structure Stability Regression Tests
# =============================================================================


def test_regression_evaluate_response_dto_container_stability(
    engine: RiskEngineFacade, canonical_evidence: RiskEvidence
):
    """Regression test: evaluate_response() maintains stable RiskEngineResponse container DTO structure."""
    # Act
    response = engine.evaluate_response(canonical_evidence)

    # Assert
    assert isinstance(response, RiskEngineResponse)
    assert isinstance(response.assessment, RiskAssessment)
    assert isinstance(response.recommendation, RiskRecommendation)
    assert isinstance(response.recommendation.action, RecommendedAction)
    assert isinstance(response.recommendation.priority, int)
    assert isinstance(response.recommendation.requires_human_review, bool)
    assert response.telemetry is not None


# =============================================================================
# 4. Invariance & Ordering Stability Regression Tests
# =============================================================================


def test_regression_duplicate_evidence_handling_stability(engine: RiskEngineFacade):
    """Regression test: Duplicate evidence processing maintains stable assessment contract."""
    # Arrange
    dup1 = RiskEvidence("ev-dup-r1", "PROMPT_FIREWALL", "DetA", "JAILBREAK", "HIGH", 0.90, 0.70, "Desc", timestamp=FIXED_TIMESTAMP)
    dup2 = RiskEvidence("ev-dup-r1", "PROMPT_FIREWALL", "DetA", "JAILBREAK", "HIGH", 0.90, 0.70, "Desc", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(dup1, dup2)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0


def test_regression_ordering_invariance_stability(engine: RiskEngineFacade):
    """Regression test: Ordering invariance holds stably across multi-item evaluations."""
    # Arrange
    ev1 = RiskEvidence("ev-r-ord-1", "PROMPT_FIREWALL", "JailbreakDetector", "JAILBREAK", "HIGH", 0.90, 0.75, "D1", timestamp=FIXED_TIMESTAMP)
    ev2 = RiskEvidence("ev-r-ord-2", "INPUT_VALIDATOR", "LengthValidator", "LENGTH_EXCEEDED", "MEDIUM", 0.80, 0.35, "D2", timestamp=FIXED_TIMESTAMP)

    # Act
    res_12 = engine.evaluate(ev1, ev2)
    res_21 = engine.evaluate(ev2, ev1)

    # Assert
    assert res_12.composite_score == res_21.composite_score
    assert res_12.confidence_score == res_21.confidence_score
    assert res_12.risk_level == res_21.risk_level
    assert res_12.recommended_action == res_21.recommended_action


# =============================================================================
# 5. Fail-Secure Behavior Regression Tests
# =============================================================================


def test_regression_fail_secure_empty_sources_raises_invalid_input(engine: RiskEngineFacade):
    """Regression test: Empty sources invocation raises InvalidRiskInputError with field details."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate()
    assert exc_info.value.details.get("field") == "sources"


def test_regression_fail_secure_invalid_payload_raises_risk_engine_error(engine: RiskEngineFacade):
    """Regression test: Invalid payload types raise domain RiskEngineError."""
    # Act & Assert
    with pytest.raises(RiskEngineError):
        engine.evaluate("unsupported_raw_string")


# =============================================================================
# 6. Multi-Instance Repeatability Regression Tests
# =============================================================================


def test_regression_multi_instance_repeatability(canonical_evidence: RiskEvidence):
    """Regression test: Evaluating canonical evidence across distinct get_risk_engine() instances produces identical results."""
    # Arrange
    engine1 = get_risk_engine()
    engine2 = get_risk_engine()

    # Act
    res1 = engine1.evaluate(canonical_evidence)
    res2 = engine2.evaluate(canonical_evidence)

    # Assert
    assert res1.composite_score == res2.composite_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.risk_level == res2.risk_level
    assert res1.recommended_action == res2.recommended_action
    assert res1.evidence == res2.evidence
