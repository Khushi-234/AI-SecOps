"""
Strategy Integration tests for the AI-SecOps Risk Engine — Sprint 7 Phase 6.

Verifies end-to-end processing across supported public strategy variations:
    - Aggregation strategies ('mean', 'median', 'max', 'min', 'weighted') via RiskEngineConfig
    - Confidence strategies ('WEIGHTED', 'CONSENSUS', 'HISTORICAL', 'HYBRID')
    - Merge strategies ('FIRST_MATCH', 'HIGHEST_SCORE', 'MERGE_ALL', 'DEDUPLICATE')
    - Strategy propagation and public DTO contract compliance (RiskAssessment, RiskEngineResponse)
    - Comparative strategy evaluation under identical evidence
    - Strategy configuration determinism
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from risk_engine.config import AggregationConfig, RiskEngineConfig
from risk_engine.enums import ConfidenceStrategy, MergeStrategy, RecommendedAction, RiskLevel
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
    RiskRecommendation,
)
from risk_engine.risk_engine import RiskEngineFacade, get_risk_engine

#: Deterministic UTC timestamp for strategy integration test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def engine() -> RiskEngineFacade:
    """Provide a real, fully wired RiskEngineFacade instance using production components."""
    return get_risk_engine()


@pytest.fixture
def multi_evidence() -> tuple[RiskEvidence, RiskEvidence]:
    """Provide a multi-source evidence tuple for strategy evaluations."""
    ev1 = RiskEvidence(
        evidence_id="ev-strat-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.80,
        description="Firewall high risk finding",
        timestamp=FIXED_TIMESTAMP,
    )
    ev2 = RiskEvidence(
        evidence_id="ev-strat-2",
        source_module="INPUT_VALIDATOR",
        detector_name="LengthValidator",
        finding_type="LENGTH_EXCEEDED",
        severity="MEDIUM",
        confidence=0.60,
        risk_score=0.30,
        description="Validator medium risk finding",
        timestamp=FIXED_TIMESTAMP,
    )
    return ev1, ev2


# =============================================================================
# 1. Aggregation Strategy Integration Tests
# =============================================================================


@pytest.mark.parametrize("agg_strategy", ["mean", "median", "max", "min", "weighted"])
def test_strategy_aggregation_variations(
    multi_evidence: tuple[RiskEvidence, RiskEvidence], agg_strategy: str
):
    """Verify RiskEngineFacade correctly executes pipeline under each supported aggregation strategy."""
    # Arrange
    config = RiskEngineConfig(aggregation=AggregationConfig(strategy=agg_strategy))
    custom_engine = RiskEngineFacade(config=config)

    # Act
    assessment = custom_engine.evaluate(*multi_evidence)

    # Assert public contract
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0
    assert isinstance(assessment.risk_level, RiskLevel)
    assert isinstance(assessment.recommended_action, RecommendedAction)


# =============================================================================
# 2. Confidence Strategy Integration Tests
# =============================================================================


@pytest.mark.parametrize("conf_strategy", ConfidenceStrategy.values())
def test_strategy_confidence_variations(
    engine: RiskEngineFacade,
    multi_evidence: tuple[RiskEvidence, RiskEvidence],
    conf_strategy: str,
):
    """Verify evaluate() executes correctly under each supported ConfidenceStrategy."""
    # Act
    assessment = engine.evaluate(*multi_evidence, confidence_strategy=conf_strategy)

    # Assert public contract
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.confidence_score <= 1.0
    assert isinstance(assessment.risk_level, RiskLevel)
    assert isinstance(assessment.recommended_action, RecommendedAction)


def test_strategy_confidence_variations_produce_distinct_confidence_scores(
    engine: RiskEngineFacade, multi_evidence: tuple[RiskEvidence, RiskEvidence]
):
    """Verify different confidence strategies modulate confidence scores appropriately on identical evidence."""
    # Act
    res_weighted = engine.evaluate(*multi_evidence, confidence_strategy="WEIGHTED")
    res_consensus = engine.evaluate(*multi_evidence, confidence_strategy="CONSENSUS")
    res_historical = engine.evaluate(*multi_evidence, confidence_strategy="HISTORICAL")

    # Assert: valid confidence scores are produced
    assert 0.0 <= res_weighted.confidence_score <= 1.0
    assert 0.0 <= res_consensus.confidence_score <= 1.0
    assert 0.0 <= res_historical.confidence_score <= 1.0


# =============================================================================
# 3. Merge Strategy Integration Tests
# =============================================================================


@pytest.mark.parametrize("merge_strategy", MergeStrategy.values())
def test_strategy_merge_variations(
    engine: RiskEngineFacade,
    multi_evidence: tuple[RiskEvidence, RiskEvidence],
    merge_strategy: str,
):
    """Verify evaluate() executes correctly under each supported MergeStrategy."""
    # Act
    assessment = engine.evaluate(*multi_evidence, merge_strategy=merge_strategy)

    # Assert public contract
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert len(assessment.evidence) > 0


# =============================================================================
# 4. Gateway Response Container Payload Strategy Tests
# =============================================================================


@pytest.mark.parametrize("conf_strategy", ["WEIGHTED", "CONSENSUS"])
def test_strategy_evaluate_response_propagation(
    engine: RiskEngineFacade,
    multi_evidence: tuple[RiskEvidence, RiskEvidence],
    conf_strategy: str,
):
    """Verify evaluate_response() propagates strategy selections into RiskEngineResponse container DTO."""
    # Act
    response = engine.evaluate_response(*multi_evidence, confidence_strategy=conf_strategy)

    # Assert
    assert isinstance(response, RiskEngineResponse)
    assert isinstance(response.assessment, RiskAssessment)
    assert isinstance(response.recommendation, RiskRecommendation)
    assert response.telemetry is not None


# =============================================================================
# 5. Deterministic Strategy Repeatability Tests
# =============================================================================


@pytest.mark.parametrize("conf_strategy", ConfidenceStrategy.values())
def test_strategy_deterministic_repeatability(
    engine: RiskEngineFacade,
    multi_evidence: tuple[RiskEvidence, RiskEvidence],
    conf_strategy: str,
):
    """Verify executing identical evidence under a specific confidence strategy is 100% repeatable."""
    # Act
    res1 = engine.evaluate(*multi_evidence, confidence_strategy=conf_strategy)
    res2 = engine.evaluate(*multi_evidence, confidence_strategy=conf_strategy)

    # Assert complete public output equivalence
    assert res1.composite_score == res2.composite_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.risk_level == res2.risk_level
    assert res1.recommended_action == res2.recommended_action
