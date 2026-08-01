"""
Unit tests for risk_engine.engine — Sprint 7 Verification Phase.

Tests orchestration behavior of RiskEngine facade:
    - Dependency injection and mandatory configuration validation (RiskEngineConfigurationError)
    - End-to-end pipeline coordination (Aggregator -> Scorer -> ConfidenceCalculator -> PolicyMapper)
    - Argument propagation and collaborator interaction verification
    - Return model verification (RiskAssessment and RiskEngineResponse)
    - Fail-secure error handling and short-circuit verification (downstream collaborators not called on upstream failure)
    - Empty input payload validation (InvalidRiskInputError)
    - Deterministic execution repeatability with fixed timestamps
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest

from risk_engine.aggregation import RiskAggregator
from risk_engine.base_scorer import BaseScorer
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.engine import RiskEngine
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import (
    InvalidRiskInputError,
    RiskEngineConfigurationError,
    RiskEngineExecutionError,
)
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
    RiskRecommendation,
    RiskScore,
)
from risk_engine.policy_mapper import PolicyMapper

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_aggregator() -> MagicMock:
    """Provide a mock RiskAggregator instance."""
    agg = MagicMock(spec=RiskAggregator)
    agg.aggregate.return_value = [
        RiskEvidence(
            evidence_id="ev-eng-1",
            source_module="PROMPT_FIREWALL",
            detector_name="JailbreakDetector",
            finding_type="JAILBREAK",
            severity="HIGH",
            confidence=0.90,
            risk_score=0.70,
            description="Sample evidence for engine orchestration",
            timestamp=FIXED_TIMESTAMP,
        )
    ]
    return agg


@pytest.fixture
def mock_scorer() -> MagicMock:
    """Provide a mock CompositeScorer/BaseScorer instance."""
    scorer = MagicMock(spec=BaseScorer)
    scorer.score.return_value = RiskScore(
        scoring_strategy="CompositeScorer",
        raw_score=0.70,
        normalized_score=0.70,
        weight=1.0,
        confidence=0.90,
    )
    return scorer


@pytest.fixture
def mock_confidence_calculator() -> MagicMock:
    """Provide a mock ConfidenceCalculator instance."""
    calc = MagicMock(spec=ConfidenceCalculator)
    calc.calculate.return_value = 0.90
    return calc


@pytest.fixture
def mock_policy_mapper() -> MagicMock:
    """Provide a mock PolicyMapper instance."""
    mapper = MagicMock(spec=PolicyMapper)
    rec = RiskRecommendation(
        action=RecommendedAction.BLOCK,
        reason="HIGH risk level confirmed with high confidence. Block recommended.",
        priority=7,
        requires_human_review=False,
    )
    mapper.map_policy.return_value = (RiskLevel.HIGH, RecommendedAction.BLOCK, rec)
    return mapper


@pytest.fixture
def engine(
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
) -> RiskEngine:
    """Provide a RiskEngine instance with fully mocked dependencies."""
    return RiskEngine(
        aggregator=mock_aggregator,
        scorer=mock_scorer,
        confidence_calculator=mock_confidence_calculator,
        policy_mapper=mock_policy_mapper,
    )


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-eng-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Sample evidence for engine orchestration",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Initialization & Configuration Validation Tests
# =============================================================================


def test_engine_initialization_with_mocks(engine: RiskEngine):
    """Verify RiskEngine initializes properly when mandatory dependencies are injected."""
    # Assert
    assert isinstance(engine, RiskEngine)


def test_engine_missing_scorer_raises_configuration_error(mock_policy_mapper: MagicMock):
    """Verify initializing RiskEngine without a scorer raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        RiskEngine(scorer=None, policy_mapper=mock_policy_mapper)
    assert exc_info.value.details.get("field") == "scorer"


def test_engine_missing_policy_mapper_raises_configuration_error(mock_scorer: MagicMock):
    """Verify initializing RiskEngine without a policy_mapper raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        RiskEngine(scorer=mock_scorer, policy_mapper=None)
    assert exc_info.value.details.get("field") == "policy_mapper"


# =============================================================================
# 2. Pipeline Orchestration & Collaborator Verification Tests
# =============================================================================


def test_engine_evaluate_orchestrates_all_collaborators(
    engine: RiskEngine,
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify evaluate() invokes all collaborators in sequence with correct arguments."""
    # Arrange
    raw_findings = [sample_evidence]

    # Act
    assessment = engine.evaluate(raw_findings, merge_strategy="HIGHEST_SCORE", confidence_strategy="WEIGHTED")

    # Assert
    assert isinstance(assessment, RiskAssessment)
    mock_aggregator.aggregate.assert_called_once_with(raw_findings, merge_strategy="HIGHEST_SCORE")
    mock_scorer.score.assert_called_once_with(mock_aggregator.aggregate.return_value)
    mock_confidence_calculator.calculate.assert_called_once_with(
        mock_aggregator.aggregate.return_value, strategy="WEIGHTED"
    )
    mock_policy_mapper.map_policy.assert_called_once_with(
        0.70, 0.90, mock_aggregator.aggregate.return_value
    )


def test_engine_evaluate_returns_valid_risk_assessment(
    engine: RiskEngine, sample_evidence: RiskEvidence
):
    """Verify evaluate() returns a complete, fully populated RiskAssessment DTO."""
    # Act
    assessment = engine.evaluate([sample_evidence])

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert assessment.composite_score == 0.70
    assert assessment.confidence_score == 0.90
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.recommended_action == RecommendedAction.BLOCK
    assert len(assessment.evidence) == 1
    assert isinstance(assessment.scores[0], RiskScore)


def test_engine_evaluate_response_returns_valid_response(
    engine: RiskEngine, sample_evidence: RiskEvidence
):
    """Verify evaluate_response() returns a canonical RiskEngineResponse container."""
    # Act
    response = engine.evaluate_response([sample_evidence])

    # Assert
    assert isinstance(response, RiskEngineResponse)
    assert isinstance(response.assessment, RiskAssessment)
    assert response.assessment.composite_score == 0.70
    assert isinstance(response.recommendation, RiskRecommendation)
    assert response.recommendation.action == RecommendedAction.BLOCK


# =============================================================================
# 3. Input Validation & Short-Circuit Fail-Secure Tests
# =============================================================================


def test_engine_evaluate_empty_sources_raises_invalid_input(engine: RiskEngine):
    """Verify calling evaluate() with no sources raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate()
    assert exc_info.value.details.get("field") == "sources"


def test_engine_evaluate_aggregator_failure_prevents_downstream_calls(
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify an unexpected exception in RiskAggregator halts execution and prevents downstream calls."""
    # Arrange
    mock_aggregator.aggregate.side_effect = RuntimeError("Aggregator unexpected error")
    eng = RiskEngine(
        aggregator=mock_aggregator,
        scorer=mock_scorer,
        confidence_calculator=mock_confidence_calculator,
        policy_mapper=mock_policy_mapper,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        eng.evaluate([sample_evidence])

    # Assert short-circuiting: downstream collaborators must NOT be called
    assert exc_info.value.details.get("stage") == "orchestration"
    mock_scorer.score.assert_not_called()
    mock_confidence_calculator.calculate.assert_not_called()
    mock_policy_mapper.map_policy.assert_not_called()


def test_engine_evaluate_scorer_failure_prevents_downstream_calls(
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify an unexpected exception in CompositeScorer halts execution and prevents downstream calls."""
    # Arrange
    mock_scorer.score.side_effect = RuntimeError("Scorer unexpected error")
    eng = RiskEngine(
        aggregator=mock_aggregator,
        scorer=mock_scorer,
        confidence_calculator=mock_confidence_calculator,
        policy_mapper=mock_policy_mapper,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        eng.evaluate([sample_evidence])

    # Assert short-circuiting: downstream collaborators must NOT be called
    assert exc_info.value.details.get("stage") == "orchestration"
    mock_confidence_calculator.calculate.assert_not_called()
    mock_policy_mapper.map_policy.assert_not_called()


def test_engine_evaluate_confidence_calculator_failure_prevents_downstream_calls(
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify an unexpected exception in ConfidenceCalculator halts execution and prevents downstream calls."""
    # Arrange
    mock_confidence_calculator.calculate.side_effect = RuntimeError("ConfidenceCalculator error")
    eng = RiskEngine(
        aggregator=mock_aggregator,
        scorer=mock_scorer,
        confidence_calculator=mock_confidence_calculator,
        policy_mapper=mock_policy_mapper,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        eng.evaluate([sample_evidence])

    # Assert short-circuiting: downstream collaborator must NOT be called
    assert exc_info.value.details.get("stage") == "orchestration"
    mock_policy_mapper.map_policy.assert_not_called()


def test_engine_evaluate_policy_mapper_failure_raises_execution_error(
    mock_aggregator: MagicMock,
    mock_scorer: MagicMock,
    mock_confidence_calculator: MagicMock,
    mock_policy_mapper: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify an unexpected exception in PolicyMapper is wrapped into RiskEngineExecutionError."""
    # Arrange
    mock_policy_mapper.map_policy.side_effect = RuntimeError("PolicyMapper error")
    eng = RiskEngine(
        aggregator=mock_aggregator,
        scorer=mock_scorer,
        confidence_calculator=mock_confidence_calculator,
        policy_mapper=mock_policy_mapper,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        eng.evaluate([sample_evidence])
    assert exc_info.value.details.get("stage") == "orchestration"


# =============================================================================
# 4. Deterministic Repeatability Tests
# =============================================================================


def test_engine_evaluate_deterministic_repeatability(
    engine: RiskEngine, sample_evidence: RiskEvidence
):
    """Verify multiple evaluate() calls with identical inputs produce identical assessment outputs."""
    # Act
    res1 = engine.evaluate([sample_evidence])
    res2 = engine.evaluate([sample_evidence])

    # Assert
    assert res1.composite_score == res2.composite_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.risk_level == res2.risk_level
    assert res1.recommended_action == res2.recommended_action
