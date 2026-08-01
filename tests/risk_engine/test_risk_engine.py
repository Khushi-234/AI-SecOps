"""
Unit tests for risk_engine.risk_engine — Sprint 7 Verification Phase.

Tests public facade API behavior of RiskEngineFacade and get_risk_engine factory:
    - Facade initialization and dependency wiring (default config, custom config, injected internal engine)
    - get_risk_engine() factory function (instance creation, unique instance generation, and custom config support)
    - evaluate() public facade delegation to internal RiskEngine orchestrator
    - evaluate_response() public facade delegation to internal RiskEngine orchestrator
    - health() service status check and version() metadata inspection
    - Structured exception propagation for evaluate() and evaluate_response() (InvalidRiskInputError, RiskEngineExecutionError)
    - Deterministic execution repeatability with fixed timestamps
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any
from unittest.mock import MagicMock
import pytest

from risk_engine.config import RiskEngineConfig
from risk_engine.engine import RiskEngine as InternalRiskEngine
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import InvalidRiskInputError, RiskEngineExecutionError
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
    RiskRecommendation,
    RiskTelemetry,
)
from risk_engine.risk_engine import RiskEngineFacade, get_risk_engine

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

#: Regular expression pattern for semantic versioning validation
SEMVER_REGEX: str = r"^\d+\.\d+\.\d+"


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_internal_engine() -> MagicMock:
    """Provide a mock InternalRiskEngine instance."""
    mock_engine = MagicMock(spec=InternalRiskEngine)

    sample_evidence = RiskEvidence(
        evidence_id="ev-facade-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Facade test evidence",
        timestamp=FIXED_TIMESTAMP,
    )

    assessment = RiskAssessment(
        assessment_id="test-assessment-id",
        composite_score=0.70,
        confidence_score=0.90,
        risk_level=RiskLevel.HIGH,
        recommended_action=RecommendedAction.BLOCK,
        evidence=(sample_evidence,),
        scores=(),
        metadata={},
        timestamp=FIXED_TIMESTAMP,
    )

    recommendation = RiskRecommendation(
        action=RecommendedAction.BLOCK,
        reason="HIGH risk level confirmed. Block recommended.",
        priority=7,
        requires_human_review=False,
    )

    telemetry = RiskTelemetry(
        execution_time_ms=1.5,
        scoring_strategy="COMPOSITE",
        aggregation_strategy="mean",
        confidence_strategy="WEIGHTED",
        processed_evidence_count=1,
    )

    response = RiskEngineResponse(
        assessment=assessment,
        recommendation=recommendation,
        telemetry=telemetry,
        timestamp=FIXED_TIMESTAMP,
    )

    mock_engine.evaluate.return_value = assessment
    mock_engine.evaluate_response.return_value = response
    return mock_engine


@pytest.fixture
def facade(mock_internal_engine: MagicMock) -> RiskEngineFacade:
    """Provide a RiskEngineFacade instance injected with a mock internal engine."""
    return RiskEngineFacade(engine=mock_internal_engine)


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-facade-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.70,
        description="Facade test evidence",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Initialization & Factory Tests
# =============================================================================


def test_facade_initialization_with_mock_engine(facade: RiskEngineFacade):
    """Verify RiskEngineFacade initializes properly when provided an internal engine."""
    # Assert
    assert isinstance(facade, RiskEngineFacade)


def test_facade_default_initialization():
    """Verify RiskEngineFacade initializes with default dependencies when no engine is passed."""
    # Act
    facade_default = RiskEngineFacade()

    # Assert
    assert isinstance(facade_default, RiskEngineFacade)


def test_facade_custom_config_initialization():
    """Verify RiskEngineFacade accepts a custom RiskEngineConfig."""
    # Arrange
    custom_cfg = RiskEngineConfig()

    # Act
    facade_custom = RiskEngineFacade(config=custom_cfg)

    # Assert
    assert isinstance(facade_custom, RiskEngineFacade)


def test_get_risk_engine_factory():
    """Verify get_risk_engine() returns a ready-to-use RiskEngineFacade instance and generates new instances."""
    # Act
    inst1 = get_risk_engine()
    inst2 = get_risk_engine()

    # Assert
    assert isinstance(inst1, RiskEngineFacade)
    assert isinstance(inst2, RiskEngineFacade)
    assert inst1 is not inst2


def test_get_risk_engine_factory_with_custom_config():
    """Verify get_risk_engine() accepts custom configuration."""
    # Arrange
    custom_cfg = RiskEngineConfig()

    # Act
    engine_from_factory = get_risk_engine(config=custom_cfg)

    # Assert
    assert isinstance(engine_from_factory, RiskEngineFacade)


# =============================================================================
# 2. Public API Delegation Tests (evaluate & evaluate_response)
# =============================================================================


def test_facade_evaluate_delegates_to_internal_engine(
    facade: RiskEngineFacade,
    mock_internal_engine: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify facade.evaluate() forwards sources and strategies to internal engine."""
    # Arrange
    raw_sources = [sample_evidence]

    # Act
    assessment = facade.evaluate(raw_sources, merge_strategy="HIGHEST_SCORE", confidence_strategy="WEIGHTED")

    # Assert
    assert isinstance(assessment, RiskAssessment)
    mock_internal_engine.evaluate.assert_called_once_with(
        raw_sources, merge_strategy="HIGHEST_SCORE", confidence_strategy="WEIGHTED"
    )


def test_facade_evaluate_response_delegates_to_internal_engine(
    facade: RiskEngineFacade,
    mock_internal_engine: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify facade.evaluate_response() forwards sources and strategies to internal engine."""
    # Arrange
    raw_sources = [sample_evidence]

    # Act
    response = facade.evaluate_response(raw_sources, merge_strategy="MERGE_ALL", confidence_strategy="CONSENSUS")

    # Assert
    assert isinstance(response, RiskEngineResponse)
    mock_internal_engine.evaluate_response.assert_called_once_with(
        raw_sources, merge_strategy="MERGE_ALL", confidence_strategy="CONSENSUS"
    )


# =============================================================================
# 3. Service Health & Version Inspection Tests
# =============================================================================


def test_facade_health_returns_valid_contract(facade: RiskEngineFacade):
    """Verify health() returns payload adhering to public contract (required keys and value types)."""
    # Act
    health_info = facade.health()

    # Assert
    assert isinstance(health_info, dict)
    assert "status" in health_info
    assert isinstance(health_info["status"], str)
    assert "initialized" in health_info
    assert isinstance(health_info["initialized"], bool)
    assert "version" in health_info
    assert isinstance(health_info["version"], str)
    assert "available_strategies" in health_info
    assert isinstance(health_info["available_strategies"], (list, tuple))
    assert "configuration_loaded" in health_info
    assert isinstance(health_info["configuration_loaded"], bool)


def test_facade_version_returns_valid_semver_string(facade: RiskEngineFacade):
    """Verify version() returns non-empty, non-whitespace string matching semantic versioning format."""
    # Act
    ver = facade.version()

    # Assert
    assert isinstance(ver, str)
    stripped_ver = ver.strip()
    assert len(stripped_ver) > 0
    assert re.match(SEMVER_REGEX, stripped_ver) is not None


# =============================================================================
# 4. Structured Exception Propagation Tests
# =============================================================================


def test_facade_evaluate_propagates_invalid_input_error(
    facade: RiskEngineFacade, mock_internal_engine: MagicMock
):
    """Verify facade.evaluate() propagates InvalidRiskInputError with structured fields."""
    # Arrange
    mock_internal_engine.evaluate.side_effect = InvalidRiskInputError(
        message="Input sources cannot be empty.", field="sources", value=[]
    )

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        facade.evaluate()
    assert exc_info.value.details.get("field") == "sources"


def test_facade_evaluate_propagates_execution_error(
    facade: RiskEngineFacade,
    mock_internal_engine: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify facade.evaluate() propagates RiskEngineExecutionError with structured fields."""
    # Arrange
    mock_internal_engine.evaluate.side_effect = RiskEngineExecutionError(
        message="Internal engine execution failed.", details={"stage": "orchestration"}
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        facade.evaluate([sample_evidence])
    assert exc_info.value.details.get("stage") == "orchestration"


def test_facade_evaluate_response_propagates_invalid_input_error(
    facade: RiskEngineFacade, mock_internal_engine: MagicMock
):
    """Verify facade.evaluate_response() propagates InvalidRiskInputError with structured fields."""
    # Arrange
    mock_internal_engine.evaluate_response.side_effect = InvalidRiskInputError(
        message="Input sources cannot be empty.", field="sources", value=[]
    )

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        facade.evaluate_response()
    assert exc_info.value.details.get("field") == "sources"


def test_facade_evaluate_response_propagates_execution_error(
    facade: RiskEngineFacade,
    mock_internal_engine: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify facade.evaluate_response() propagates RiskEngineExecutionError with structured fields."""
    # Arrange
    mock_internal_engine.evaluate_response.side_effect = RiskEngineExecutionError(
        message="Internal engine execution failed.", details={"stage": "orchestration"}
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        facade.evaluate_response([sample_evidence])
    assert exc_info.value.details.get("stage") == "orchestration"


# =============================================================================
# 5. Deterministic Repeatability Tests
# =============================================================================


def test_facade_evaluate_deterministic_repeatability(
    facade: RiskEngineFacade, sample_evidence: RiskEvidence
):
    """Verify repeated evaluate calls with identical inputs produce identical RiskAssessment DTO fields."""
    # Act
    res1 = facade.evaluate([sample_evidence])
    res2 = facade.evaluate([sample_evidence])

    # Assert
    assert res1.composite_score == res2.composite_score
    assert res1.confidence_score == res2.confidence_score
    assert res1.risk_level == res2.risk_level
    assert res1.recommended_action == res2.recommended_action
    assert res1.evidence == res2.evidence


def test_facade_evaluate_response_deterministic_repeatability(
    facade: RiskEngineFacade, sample_evidence: RiskEvidence
):
    """Verify repeated evaluate_response calls with identical inputs produce identical RiskEngineResponse DTO fields."""
    # Act
    resp1 = facade.evaluate_response([sample_evidence])
    resp2 = facade.evaluate_response([sample_evidence])

    # Assert
    assert resp1.assessment.composite_score == resp2.assessment.composite_score
    assert resp1.assessment.risk_level == resp2.assessment.risk_level
    assert resp1.recommendation.action == resp2.recommendation.action
    assert resp1.recommendation.priority == resp2.recommendation.priority
