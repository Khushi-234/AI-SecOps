"""
Unit tests for risk_engine.aggregation — Sprint 7 Verification Phase.

Tests all public behavior of RiskAggregator:
    - Multi-source finding ingestion (*sources)
    - Input validation & empty/None payload handling
    - Normalization of heterogeneous finding DTOs (RiskEvidence, ValidationResult, DetectionResult, Dicts)
    - Duplicate detection and merge strategies (HIGHEST_SCORE, FIRST_MATCH, MERGE_ALL, DEDUPLICATE)
    - Deterministic sorting rules (Score -> Confidence -> Severity Rank -> Identity)
    - Fail-secure error propagation (InvalidRiskInputError, RiskAggregationError)
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from input_validator.models import ValidationResult
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.models import DetectionResult

from risk_engine.aggregation import RiskAggregator
from risk_engine.enums import EvidenceSource, MergeStrategy
from risk_engine.exceptions import InvalidRiskInputError, RiskAggregationError
from risk_engine.models import RiskEvidence


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def aggregator() -> RiskAggregator:
    """Provide a default RiskAggregator instance for unit tests."""
    return RiskAggregator()


@pytest.fixture
def sample_risk_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-100",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.9,
        description="Jailbreak pattern detected",
        metadata={"matched_text": "Ignore previous instructions"},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_validation_result() -> ValidationResult:
    """Provide a canonical ValidationResult fixture."""
    return ValidationResult(
        validator_name="LengthValidator",
        is_valid=False,
        error_message="Prompt length exceeds 1000 character limit.",
        execution_time_ms=1.2,
        timestamp=datetime.now(timezone.utc),
        metadata={"severity": "HIGH", "confidence": 0.85, "finding_type": "LENGTH_LIMIT_EXCEEDED"},
    )


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    """Provide a canonical DetectionResult fixture."""
    return DetectionResult(
        request_id="req-999",
        detector_name="PromptInjectionDetector",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=0.90,
        matched_text="System override command",
        evidence="Prompt injection pattern matched",
        execution_time_ms=3.4,
        status=DetectionStatus.SUCCESS,
        timestamp=datetime.now(timezone.utc),
    )


# =============================================================================
# 1. Empty & Invalid Input Tests
# =============================================================================


def test_aggregate_empty_sources_raises_error(aggregator: RiskAggregator):
    """Verify calling aggregate() without any arguments raises an exception."""
    # Arrange & Act & Assert
    with pytest.raises(Exception):
        aggregator.aggregate()


def test_aggregate_none_only_sources_raises_error(aggregator: RiskAggregator):
    """Verify calling aggregate(None, None) raises an exception."""
    # Arrange & Act & Assert
    with pytest.raises(Exception):
        aggregator.aggregate(None, None)


def test_aggregate_empty_containers_raises_error(aggregator: RiskAggregator):
    """Verify calling aggregate([], []) raises an exception."""
    # Arrange & Act & Assert
    with pytest.raises(Exception):
        aggregator.aggregate([], [])


# =============================================================================
# 2. Single Item Ingestion & Normalization Tests
# =============================================================================


def test_aggregate_single_risk_evidence(
    aggregator: RiskAggregator, sample_risk_evidence: RiskEvidence
):
    """Verify aggregating a single RiskEvidence returns an equivalent RiskEvidence item."""
    # Act
    results = aggregator.aggregate(sample_risk_evidence)

    # Assert
    assert len(results) == 1
    assert results[0].evidence_id == sample_risk_evidence.evidence_id
    assert results[0].source_module == sample_risk_evidence.source_module
    assert results[0].risk_score == sample_risk_evidence.risk_score
    assert results[0].confidence == sample_risk_evidence.confidence


def test_aggregate_single_validation_result(
    aggregator: RiskAggregator, sample_validation_result: ValidationResult
):
    """Verify aggregating a ValidationResult normalizes into a valid RiskEvidence object."""
    # Act
    results = aggregator.aggregate(sample_validation_result)

    # Assert
    assert len(results) == 1
    evidence = results[0]
    assert isinstance(evidence, RiskEvidence)
    assert evidence.source_module == EvidenceSource.INPUT_VALIDATOR.value
    assert evidence.detector_name == "LengthValidator"
    assert evidence.severity == "HIGH"
    assert evidence.confidence == 0.85
    assert evidence.risk_score == 0.7  # HIGH severity default score


def test_aggregate_single_detection_result(
    aggregator: RiskAggregator, sample_detection_result: DetectionResult
):
    """Verify aggregating a DetectionResult normalizes into a valid RiskEvidence object."""
    # Act
    results = aggregator.aggregate(sample_detection_result)

    # Assert
    assert len(results) == 1
    evidence = results[0]
    assert isinstance(evidence, RiskEvidence)
    assert evidence.source_module == EvidenceSource.PROMPT_FIREWALL.value
    assert evidence.detector_name == "PromptInjectionDetector"
    assert evidence.severity == "HIGH"
    assert evidence.confidence == 0.90
    assert evidence.metadata.get("matched_text") == "System override command"


def test_aggregate_single_dict_finding(aggregator: RiskAggregator):
    """Verify aggregating a raw dictionary finding normalizes into a RiskEvidence object."""
    # Arrange
    dict_finding = {
        "source_module": "INPUT_VALIDATOR",
        "detector_name": "CustomFormatValidator",
        "finding_type": "FORMAT_ANOMALY",
        "risk_score": 0.65,
        "severity": "MEDIUM",
        "confidence": 0.80,
        "description": "Custom format anomaly detected",
    }

    # Act
    results = aggregator.aggregate(dict_finding)

    # Assert
    assert len(results) == 1
    evidence = results[0]
    assert isinstance(evidence, RiskEvidence)
    assert evidence.detector_name == "CustomFormatValidator"
    assert evidence.risk_score == 0.65
    assert evidence.severity == "MEDIUM"


# =============================================================================
# 3. Multi-Source & Heterogeneous Source Ingestion Tests
# =============================================================================


def test_aggregate_heterogeneous_sources(
    aggregator: RiskAggregator,
    sample_risk_evidence: RiskEvidence,
    sample_validation_result: ValidationResult,
    sample_detection_result: DetectionResult,
):
    """Verify aggregate() ingests a mix of RiskEvidence, ValidationResult, DetectionResult, and dicts."""
    # Arrange
    dict_finding = {
        "source_module": "CUSTOM",
        "detector_name": "AnomalyDetector",
        "finding_type": "ANOMALY",
        "risk_score": 0.3,
        "severity": "LOW",
        "confidence": 0.75,
        "description": "Custom low risk anomaly",
    }

    # Act
    results = aggregator.aggregate(
        sample_risk_evidence,
        [sample_validation_result, sample_detection_result],
        dict_finding,
    )

    # Assert
    assert len(results) == 4
    for item in results:
        assert isinstance(item, RiskEvidence)


def test_aggregate_nested_iterables(
    aggregator: RiskAggregator, sample_risk_evidence: RiskEvidence
):
    """Verify recursively nested lists and iterables are unwrapped correctly."""
    # Arrange
    nested = [[sample_risk_evidence], (sample_risk_evidence,), [sample_risk_evidence]]

    # Act
    results = aggregator.aggregate(nested, merge_strategy=MergeStrategy.MERGE_ALL)

    # Assert
    assert len(results) == 3


# =============================================================================
# 4. Merge Strategy & Deduplication Tests
# =============================================================================


@pytest.mark.parametrize(
    "strategy, expected_score, expected_confidence, expected_count",
    [
        (MergeStrategy.HIGHEST_SCORE, 0.95, 0.90, 1),
        (MergeStrategy.FIRST_MATCH, 0.70, 0.90, 1),
        (MergeStrategy.MERGE_ALL, 0.70, 0.90, 2),
        (MergeStrategy.DEDUPLICATE, 0.95, 0.90, 1),
    ],
)
def test_aggregate_merge_strategies(
    aggregator: RiskAggregator,
    strategy: MergeStrategy,
    expected_score: float,
    expected_confidence: float,
    expected_count: int,
):
    """Verify each MergeStrategy resolves duplicate findings correctly."""
    # Arrange: two findings sharing identical compound key fingerprint
    finding1 = RiskEvidence(
        evidence_id="ev-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.70,
        description="First finding",
        metadata={"matched_text": "Ignore prompt"},
    )
    finding2 = RiskEvidence(
        evidence_id="ev-2",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="CRITICAL",
        confidence=0.90,
        risk_score=0.95,
        description="Second finding",
        metadata={"matched_text": "Ignore prompt"},
    )

    # Act
    results = aggregator.aggregate(finding1, finding2, merge_strategy=strategy)

    # Assert
    assert len(results) == expected_count
    if expected_count == 1:
        assert results[0].risk_score == expected_score
        assert results[0].confidence == expected_confidence


@pytest.mark.parametrize("strategy_str", ["HIGHEST_SCORE", "FIRST_MATCH", "MERGE_ALL", "DEDUPLICATE"])
def test_aggregate_merge_strategy_strings(aggregator: RiskAggregator, sample_risk_evidence: RiskEvidence, strategy_str: str):
    """Verify merge_strategy can be passed as uppercase string designations."""
    # Act
    results = aggregator.aggregate(sample_risk_evidence, merge_strategy=strategy_str)

    # Assert
    assert len(results) == 1


# =============================================================================
# 5. Deterministic Sorting Tests
# =============================================================================


def test_aggregate_deterministic_sorting(aggregator: RiskAggregator):
    """Verify aggregated evidence is sorted deterministically by risk_score desc, confidence desc, severity desc."""
    # Arrange
    low_item = RiskEvidence(
        evidence_id="ev-low",
        source_module="INPUT_VALIDATOR",
        detector_name="LowDetector",
        finding_type="LOW",
        severity="LOW",
        confidence=0.5,
        risk_score=0.2,
        description="Low finding",
    )
    high_item = RiskEvidence(
        evidence_id="ev-high",
        source_module="PROMPT_FIREWALL",
        detector_name="HighDetector",
        finding_type="HIGH",
        severity="HIGH",
        confidence=0.8,
        risk_score=0.8,
        description="High finding",
    )
    critical_item = RiskEvidence(
        evidence_id="ev-crit",
        source_module="PROMPT_FIREWALL",
        detector_name="CritDetector",
        finding_type="CRITICAL",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.95,
        description="Critical finding",
    )

    # Act: pass items in reverse order
    results = aggregator.aggregate(low_item, critical_item, high_item)

    # Assert: items must be ordered Critical -> High -> Low
    assert results[0].evidence_id == "ev-crit"
    assert results[1].evidence_id == "ev-high"
    assert results[2].evidence_id == "ev-low"


def test_aggregate_repeatable_ordering(aggregator: RiskAggregator, sample_risk_evidence: RiskEvidence, sample_validation_result: ValidationResult):
    """Verify multiple calls to aggregate() with identical inputs return identical evidence ordering."""
    # Act
    run1 = aggregator.aggregate(sample_risk_evidence, sample_validation_result)
    run2 = aggregator.aggregate(sample_validation_result, sample_risk_evidence)

    # Assert
    assert [e.evidence_id for e in run1] == [e.evidence_id for e in run2]


# =============================================================================
# 6. Exception Propagation & Fail-Secure Tests
# =============================================================================


def test_aggregate_unsupported_object_raises_error(aggregator: RiskAggregator):
    """Verify passing an unparseable object raises an exception."""
    # Arrange
    invalid_object = 12345  # integer scalar cannot be normalized into RiskEvidence

    # Act & Assert
    with pytest.raises(Exception):
        aggregator.aggregate(invalid_object)


def test_aggregate_invalid_merge_strategy_string_raises(aggregator: RiskAggregator, sample_risk_evidence: RiskEvidence):
    """Verify passing an invalid merge strategy string raises an exception."""
    # Act & Assert
    with pytest.raises(Exception):
        aggregator.aggregate(sample_risk_evidence, merge_strategy="NON_EXISTENT_STRATEGY")
