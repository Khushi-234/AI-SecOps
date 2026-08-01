"""
End-to-End Integration tests for the AI-SecOps Risk Engine — Sprint 7 Phase 6.

Integrates real production components (RiskEngineFacade, RiskEngine, RiskAggregator,
CompositeScorer, WeightedScorer, ThresholdScorer, AdaptiveScorer, ConfidenceCalculator,
PolicyMapper) to verify public end-to-end pipeline processing contract:
    Inputs -> RiskAggregator -> CompositeScorer -> ConfidenceCalculator -> PolicyMapper -> RiskAssessment / RiskEngineResponse

Test Scenarios:
    - Single findings across all RiskLevel classifications
    - Multi-source evidence aggregation and merge strategy handling
    - Ordering invariance (Evidence A + Evidence B vs Evidence B + Evidence A)
    - Graceful handling of unknown detector names and finding types
    - Confidence-aware policy evaluations
    - Full RiskEngineResponse payload assembly
    - Fail-secure error handling for empty and invalid finding payloads
    - Deterministic execution repeatability
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

#: Deterministic UTC timestamp for integration test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def engine() -> RiskEngineFacade:
    """Provide a real, fully wired RiskEngineFacade instance using production components."""
    return get_risk_engine()


# =============================================================================
# 1. Single Finding Evaluation Scenarios Across Risk Levels
# =============================================================================


@pytest.mark.parametrize(
    "risk_score, confidence, expected_level",
    [
        (0.05, 0.90, RiskLevel.LOW),
        (0.25, 0.90, RiskLevel.MEDIUM),
        (0.55, 0.90, RiskLevel.HIGH),
        (0.85, 0.90, RiskLevel.CRITICAL),
    ],
)
def test_e2e_single_finding_risk_levels(
    engine: RiskEngineFacade,
    risk_score: float,
    confidence: float,
    expected_level: RiskLevel,
):
    """Verify end-to-end processing of a single evidence finding produces valid public assessment DTO."""
    # Arrange
    evidence = RiskEvidence(
        evidence_id="ev-e2e-single",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=confidence,
        risk_score=risk_score,
        description="Single finding integration test item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(evidence)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert assessment.risk_level == expected_level
    assert isinstance(assessment.recommended_action, RecommendedAction)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0
    assert len(assessment.evidence) == 1


# =============================================================================
# 2. Multi-Source Aggregation, Merge Strategy, and Ordering Invariance
# =============================================================================


def test_e2e_multiple_evidence_aggregation(engine: RiskEngineFacade):
    """Verify end-to-end processing and aggregation of findings from multiple security modules."""
    # Arrange
    ev1 = RiskEvidence(
        evidence_id="ev-fw-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.95,
        risk_score=0.80,
        description="Firewall jailbreak detection",
        timestamp=FIXED_TIMESTAMP,
    )
    ev2 = RiskEvidence(
        evidence_id="ev-val-1",
        source_module="INPUT_VALIDATOR",
        detector_name="LengthValidator",
        finding_type="LENGTH_EXCEEDED",
        severity="MEDIUM",
        confidence=0.85,
        risk_score=0.40,
        description="Input validator length anomaly",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(ev1, ev2)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert len(assessment.evidence) == 2
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0


def test_e2e_ordering_invariance(engine: RiskEngineFacade):
    """Verify evaluating Evidence (A, B) vs (B, A) yields identical public assessment outcomes."""
    # Arrange
    ev1 = RiskEvidence(
        evidence_id="ev-ord-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.80,
        description="First item",
        timestamp=FIXED_TIMESTAMP,
    )
    ev2 = RiskEvidence(
        evidence_id="ev-ord-2",
        source_module="INPUT_VALIDATOR",
        detector_name="LengthValidator",
        finding_type="LENGTH_EXCEEDED",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.40,
        description="Second item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    res_ab = engine.evaluate(ev1, ev2)
    res_ba = engine.evaluate(ev2, ev1)

    # Assert ordering invariance
    assert res_ab.composite_score == res_ba.composite_score
    assert res_ab.confidence_score == res_ba.confidence_score
    assert res_ab.risk_level == res_ba.risk_level
    assert res_ab.recommended_action == res_ba.recommended_action


def test_e2e_duplicate_evidence_handling(engine: RiskEngineFacade):
    """Verify duplicate evidence items are processed via public merge strategy API without errors."""
    # Arrange: two findings with matching identity
    dup1 = RiskEvidence(
        evidence_id="ev-dup-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Duplicate finding 1",
        timestamp=FIXED_TIMESTAMP,
    )
    dup2 = RiskEvidence(
        evidence_id="ev-dup-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Duplicate finding 1 copy",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(dup1, dup2, merge_strategy="HIGHEST_SCORE")

    # Assert public contract
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0


# =============================================================================
# 3. Graceful Unknown Detector & Finding Type Handling
# =============================================================================


def test_e2e_unknown_detector_and_finding_types(engine: RiskEngineFacade):
    """Verify engine gracefully processes evidence with unknown detector names and finding types without failing."""
    # Arrange
    unknown_ev = RiskEvidence(
        evidence_id="ev-unk-1",
        source_module="CUSTOM_PLUGIN",
        detector_name="CustomZeroDayDetector3000",
        finding_type="UNKNOWN_THREAT_PATTERN",
        severity="CRITICAL",
        confidence=0.80,
        risk_score=0.75,
        description="Unseen custom detector finding",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(unknown_ev)

    # Assert graceful evaluation
    assert isinstance(assessment, RiskAssessment)
    assert isinstance(assessment.risk_level, RiskLevel)
    assert isinstance(assessment.recommended_action, RecommendedAction)
    assert len(assessment.evidence) == 1
    assert assessment.evidence[0].detector_name == "CustomZeroDayDetector3000"


# =============================================================================
# 4. Confidence-Aware Policy Evaluation Scenarios
# =============================================================================


def test_e2e_low_confidence_evaluates_valid_recommendation(engine: RiskEngineFacade):
    """Verify low confidence evidence yields a valid public RiskAssessment recommendation."""
    # Arrange
    low_conf_ev = RiskEvidence(
        evidence_id="ev-esc-1",
        source_module="PROMPT_FIREWALL",
        detector_name="HeuristicDetector",
        finding_type="SUSPICIOUS_HEURISTIC",
        severity="CRITICAL",
        confidence=0.10,
        risk_score=0.85,
        description="Uncalibrated low confidence threat",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(low_conf_ev)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert isinstance(assessment.recommended_action, RecommendedAction)


def test_e2e_high_confidence_evaluates_valid_recommendation(engine: RiskEngineFacade):
    """Verify high confidence evidence yields a valid public RiskAssessment recommendation."""
    # Arrange
    high_conf_ev = RiskEvidence(
        evidence_id="ev-blk-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.85,
        description="High confidence threat",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(high_conf_ev)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert isinstance(assessment.recommended_action, RecommendedAction)


# =============================================================================
# 5. Full Gateway Response Payload Tests (evaluate_response)
# =============================================================================


def test_e2e_evaluate_response_returns_canonical_payload(engine: RiskEngineFacade):
    """Verify evaluate_response() returns a full RiskEngineResponse container with assessment, recommendation, and telemetry."""
    # Arrange
    evidence = RiskEvidence(
        evidence_id="ev-resp-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.60,
        description="Gateway response test item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    response = engine.evaluate_response(evidence)

    # Assert
    assert isinstance(response, RiskEngineResponse)
    assert isinstance(response.assessment, RiskAssessment)
    assert isinstance(response.recommendation, RiskRecommendation)
    assert response.telemetry is not None


# =============================================================================
# 6. Negative & Fail-Secure Scenarios
# =============================================================================


def test_e2e_empty_sources_raises_invalid_input(engine: RiskEngineFacade):
    """Verify calling evaluate() with empty sources raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate()
    assert exc_info.value.details.get("field") == "sources"


def test_e2e_invalid_finding_payload_raises_error(engine: RiskEngineFacade):
    """Verify passing non-parseable finding payloads raises RiskEngineError."""
    # Act & Assert
    with pytest.raises(RiskEngineError):
        engine.evaluate("not_a_valid_finding_dict_or_object")


# =============================================================================
# 7. Deterministic Repeatability Tests
# =============================================================================


def test_e2e_deterministic_repeatability(engine: RiskEngineFacade):
    """Verify repeated end-to-end evaluations with identical evidence yield identical public assessment outcomes."""
    # Arrange
    evidence = RiskEvidence(
        evidence_id="ev-repeat-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.55,
        description="Repeatability test item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    res1 = engine.evaluate(evidence)
    res2 = engine.evaluate(evidence)
    resp1 = engine.evaluate_response(evidence)
    resp2 = engine.evaluate_response(evidence)

    # Assert complete public output equivalence
    assert res1.composite_score == res2.composite_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.risk_level == res2.risk_level
    assert res1.recommended_action == res2.recommended_action
    assert res1.evidence == res2.evidence
    assert resp1.recommendation == resp2.recommendation
