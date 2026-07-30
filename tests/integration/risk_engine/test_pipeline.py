"""
Pipeline Integration tests for the AI-SecOps Risk Engine — Sprint 7 Phase 6.

Tests pipeline execution behavior of real production components:
    - Single and multi-evidence pipeline flow
    - Mixed detector and mixed source module evidence pipelines
    - Large batch evidence execution (50+ items)
    - Multi-item ordering permutation invariance
    - Duplicate evidence pipeline handling
    - Unknown detector and finding type pipeline stability
    - Mixed severity and mixed confidence propagation
    - Fail-secure empty pipeline validation (InvalidRiskInputError)
    - Pipeline execution stability and deterministic repeatability
"""

from __future__ import annotations

from datetime import datetime, timezone
import itertools
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

#: Deterministic UTC timestamp for pipeline integration test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def engine() -> RiskEngineFacade:
    """Provide a real, fully wired RiskEngineFacade instance using production components."""
    return get_risk_engine()


# =============================================================================
# 1. Pipeline Execution Across Evidence Counts & Sources
# =============================================================================


def test_pipeline_single_evidence_execution(engine: RiskEngineFacade):
    """Verify single evidence item executes smoothly through the complete pipeline."""
    # Arrange
    ev = RiskEvidence(
        evidence_id="ev-pipe-single",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.75,
        description="Single pipeline test item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(ev)

    # Assert public output DTO
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0
    assert isinstance(assessment.risk_level, RiskLevel)
    assert isinstance(assessment.recommended_action, RecommendedAction)
    assert len(assessment.evidence) == 1


def test_pipeline_mixed_sources_and_detectors_execution(engine: RiskEngineFacade):
    """Verify evidence from mixed detector names and source modules execute together."""
    # Arrange
    ev1 = RiskEvidence(
        evidence_id="ev-p1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.85,
        description="Firewall finding",
        timestamp=FIXED_TIMESTAMP,
    )
    ev2 = RiskEvidence(
        evidence_id="ev-p2",
        source_module="INPUT_VALIDATOR",
        detector_name="SqlInjectionDetector",
        finding_type="SQL_INJECTION",
        severity="HIGH",
        confidence=0.88,
        risk_score=0.70,
        description="Input validator finding",
        timestamp=FIXED_TIMESTAMP,
    )
    ev3 = RiskEvidence(
        evidence_id="ev-p3",
        source_module="OUTPUT_GUARD",
        detector_name="PiiLeakDetector",
        finding_type="PII_LEAK",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.45,
        description="Output guard finding",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    assessment = engine.evaluate(ev1, ev2, ev3)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert len(assessment.evidence) == 3
    assert 0.0 <= assessment.composite_score <= 1.0


def test_pipeline_large_batch_evidence_execution(engine: RiskEngineFacade):
    """Verify pipeline processes a large batch of 50 evidence items without memory leaks or errors."""
    # Arrange: generate 50 evidence items across 4 modules
    batch = [
        RiskEvidence(
            evidence_id=f"ev-batch-{i}",
            source_module=f"MODULE_{(i % 4) + 1}",
            detector_name=f"Detector_{i % 5}",
            finding_type=f"FINDING_TYPE_{i % 3}",
            severity=["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
            confidence=0.50 + (i % 5) * 0.10,
            risk_score=(i % 10) * 0.10,
            description=f"Large batch evidence item #{i}",
            timestamp=FIXED_TIMESTAMP,
        )
        for i in range(50)
    ]

    # Act
    assessment = engine.evaluate(batch)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert len(assessment.evidence) == 50
    assert 0.0 <= assessment.composite_score <= 1.0
    assert 0.0 <= assessment.confidence_score <= 1.0


# =============================================================================
# 2. Ordering Invariance Across Multi-Item Permutations
# =============================================================================


def test_pipeline_multi_item_ordering_permutation_invariance(engine: RiskEngineFacade):
    """Verify evaluating all 6 permutations of 3 evidence items produces identical pipeline assessment DTOs."""
    # Arrange
    ev1 = RiskEvidence("ev-perm-1", "PROMPT_FIREWALL", "JailbreakDetector", "JAILBREAK", "LOW", 0.90, 0.20, "D1", timestamp=FIXED_TIMESTAMP)
    ev2 = RiskEvidence("ev-perm-2", "INPUT_VALIDATOR", "SqlInjectionDetector", "SQL_INJECTION", "MEDIUM", 0.80, 0.50, "D2", timestamp=FIXED_TIMESTAMP)
    ev3 = RiskEvidence("ev-perm-3", "OUTPUT_GUARD", "PiiLeakDetector", "PII_LEAK", "HIGH", 0.70, 0.80, "D3", timestamp=FIXED_TIMESTAMP)

    # Act: baseline assessment
    base_res = engine.evaluate(ev1, ev2, ev3)

    # Assert: test all permutations against baseline
    for perm in itertools.permutations([ev1, ev2, ev3]):
        perm_res = engine.evaluate(*perm)
        assert perm_res.composite_score == base_res.composite_score
        assert perm_res.confidence_score == base_res.confidence_score
        assert perm_res.risk_level == base_res.risk_level
        assert perm_res.recommended_action == base_res.recommended_action


# =============================================================================
# 3. Duplicate & Unknown Evidence Pipeline Handling
# =============================================================================


def test_pipeline_duplicate_evidence_execution(engine: RiskEngineFacade):
    """Verify duplicate evidence items flow safely through the pipeline without breaking evaluation."""
    # Arrange
    dup1 = RiskEvidence("ev-dup-p1", "FIREWALL", "DetA", "TYPE1", "HIGH", 0.90, 0.70, "Desc", timestamp=FIXED_TIMESTAMP)
    dup2 = RiskEvidence("ev-dup-p1", "FIREWALL", "DetA", "TYPE1", "HIGH", 0.90, 0.70, "Desc", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(dup1, dup2)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.composite_score <= 1.0


def test_pipeline_unknown_detector_and_finding_type_execution(engine: RiskEngineFacade):
    """Verify evidence with unknown detector name and unknown finding type processes safely."""
    # Arrange
    unk_ev = RiskEvidence("ev-unk-p1", "UNKNOWN_MODULE", "UnseenDetector99", "UNKNOWN_FINDING", "HIGH", 0.85, 0.65, "Unknown desc", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(unk_ev)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert len(assessment.evidence) == 1
    assert assessment.evidence[0].detector_name == "UnseenDetector99"


# =============================================================================
# 4. Mixed Severity & Mixed Confidence Propagation
# =============================================================================


def test_pipeline_mixed_severity_propagation(engine: RiskEngineFacade):
    """Verify combining LOW, MEDIUM, HIGH, and CRITICAL severities produces a valid composite score."""
    # Arrange
    items = [
        RiskEvidence("ev-sev-1", "M1", "D1", "F1", "LOW", 0.90, 0.10, "Low item", timestamp=FIXED_TIMESTAMP),
        RiskEvidence("ev-sev-2", "M2", "D2", "F2", "MEDIUM", 0.85, 0.40, "Medium item", timestamp=FIXED_TIMESTAMP),
        RiskEvidence("ev-sev-3", "M3", "D3", "F3", "HIGH", 0.80, 0.70, "High item", timestamp=FIXED_TIMESTAMP),
        RiskEvidence("ev-sev-4", "M4", "D4", "F4", "CRITICAL", 0.95, 0.95, "Critical item", timestamp=FIXED_TIMESTAMP),
    ]

    # Act
    assessment = engine.evaluate(items)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert assessment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert 0.0 <= assessment.composite_score <= 1.0


def test_pipeline_mixed_confidence_propagation(engine: RiskEngineFacade):
    """Verify combining high confidence (0.95) and low confidence (0.10) evidence yields a valid aggregate confidence score."""
    # Arrange
    ev_high_conf = RiskEvidence("ev-conf-h", "M1", "D1", "F1", "HIGH", 0.95, 0.70, "High conf", timestamp=FIXED_TIMESTAMP)
    ev_low_conf = RiskEvidence("ev-conf-l", "M2", "D2", "F2", "HIGH", 0.10, 0.70, "Low conf", timestamp=FIXED_TIMESTAMP)

    # Act
    assessment = engine.evaluate(ev_high_conf, ev_low_conf)

    # Assert
    assert isinstance(assessment, RiskAssessment)
    assert 0.0 <= assessment.confidence_score <= 1.0


# =============================================================================
# 5. Fail-Secure & Empty Pipeline Validation
# =============================================================================


def test_pipeline_empty_sources_raises_invalid_input(engine: RiskEngineFacade):
    """Verify executing pipeline with no evidence sources raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        engine.evaluate()
    assert exc_info.value.details.get("field") == "sources"


# =============================================================================
# 6. Pipeline Stability & Deterministic Repeatability
# =============================================================================


def test_pipeline_repeatability_and_stability(engine: RiskEngineFacade):
    """Verify 10 repeated pipeline executions with identical evidence produce identical public assessment DTOs."""
    # Arrange
    ev1 = RiskEvidence("ev-stab-1", "MOD1", "Det1", "FIND1", "HIGH", 0.90, 0.65, "Item 1", timestamp=FIXED_TIMESTAMP)
    ev2 = RiskEvidence("ev-stab-2", "MOD2", "Det2", "FIND2", "MEDIUM", 0.85, 0.35, "Item 2", timestamp=FIXED_TIMESTAMP)

    # Act: run 10 repeated evaluations
    results = [engine.evaluate(ev1, ev2) for _ in range(10)]

    # Assert: all 10 results match result 0
    first = results[0]
    for r in results[1:]:
        assert r.composite_score == first.composite_score
        assert r.confidence_score == first.confidence_score
        assert r.risk_level == first.risk_level
        assert r.recommended_action == first.recommended_action
        assert r.evidence == first.evidence
