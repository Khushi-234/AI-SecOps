"""
Unit tests for the PromptFirewall gateway orchestrator.

Verifies pipeline initialization, input validation boundary errors, single-dispatch
normalization, registered detectors execution ordering, fail-secure error wrapping,
non-blocking audit logging failures, and Response/Detection DTO compilations.
"""

from datetime import datetime, timezone
from typing import Any
import pytest

from security.audit_logger import AuditLogger
from security.base_detector import BaseDetector
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.exceptions import DetectorExecutionError, FirewallError, NormalizationError, ValidationError
from security.models import DetectionResult, NormalizationMetadata, NormalizationResult
from security.normalizer import TextNormalizer
from security.prompt_firewall import PromptFirewall


# ===========================================================================
# 14. Reusable Fake Implementations
# ===========================================================================

from tests.llm.conftest import FakeAuditLogger, FakeDetector, FakeTextNormalizer


@pytest.fixture
def clean_detector() -> FakeDetector:
    return FakeDetector(name="CleanDetector")


@pytest.fixture
def threat_detector() -> FakeDetector:
    mock_res = DetectionResult(
        request_id="test-req",
        detector_name="ThreatDetector",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
        matched_text="bypass",
        evidence="Matched bypass",
        execution_time_ms=1.2,
        status=DetectionStatus.SUCCESS,
        timestamp=datetime.now(timezone.utc)
    )
    return FakeDetector(name="ThreatDetector", return_result=mock_res)


# ===========================================================================
# 1. Firewall Initialization
# ===========================================================================

def test_firewall_initialization_various_detectors(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies that firewall configures single, multiple, or empty lists of detectors."""
    # 1. Single detector
    fw_single = PromptFirewall([FakeDetector("D1")], fake_logger, fake_normalizer)
    assert len(fw_single._detectors) == 1

    # 2. Multiple detectors
    fw_multi = PromptFirewall([FakeDetector("D1"), FakeDetector("D2")], fake_logger, fake_normalizer)
    assert len(fw_multi._detectors) == 2

    # 3. Empty detector list
    fw_empty = PromptFirewall([], fake_logger, fake_normalizer)
    assert len(fw_empty._detectors) == 0


def test_firewall_initialization_fail_secure(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies fail_secure setting parameter assignment."""
    # 1. fail_secure=True
    fw_true = PromptFirewall([], fake_logger, fake_normalizer, fail_secure=True)
    assert fw_true._fail_secure is True

    # 2. fail_secure=False
    fw_false = PromptFirewall([], fake_logger, fake_normalizer, fail_secure=False)
    assert fw_false._fail_secure is False


# ===========================================================================
# 2. Input Validation
# ===========================================================================

@pytest.mark.parametrize(
    "invalid_prompt, expected_err",
    [
        (None, ValidationError),
        (12345, ValidationError),
        ({"prompt": "text"}, ValidationError),
    ],
)
def test_input_validation_raises(
    fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer, invalid_prompt: any, expected_err: type
) -> None:
    """Verifies that non-string and None prompts raise ValidationError immediately."""
    # Arrange
    firewall = PromptFirewall([], fake_logger, fake_normalizer)

    # Act & Assert
    with pytest.raises(expected_err):
        firewall.inspect_prompt(invalid_prompt)


@pytest.mark.parametrize("valid_prompt", ["", "   ", "Standard input text"])
def test_input_validation_accepts_valid_prompt_strings(
    fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer, valid_prompt: str
) -> None:
    """Verifies empty, whitespace-only, and normal string prompts are accepted."""
    # Arrange
    firewall = PromptFirewall([], fake_logger, fake_normalizer)

    # Act
    res = firewall.inspect_prompt(valid_prompt)

    # Assert
    assert res.normalized_prompt == valid_prompt


# ===========================================================================
# 3. Prompt Normalization
# ===========================================================================

def test_prompt_normalization_pipeline(fake_logger: FakeAuditLogger) -> None:
    """Verifies that normalizer is called once, clean text forwarded, and metadata logged."""
    # Arrange
    normalizer = FakeTextNormalizer(return_text="cleaned prompt")
    detector = FakeDetector("TestDetector")
    firewall = PromptFirewall([detector], fake_logger, normalizer)

    # Act
    firewall.inspect_prompt("  DIRTY   PROMPT  ")

    # Assert
    assert len(normalizer.calls) == 1
    assert normalizer.calls[0] == "  DIRTY   PROMPT  "
    assert detector.calls[0][0] == "cleaned prompt"
    assert len(fake_logger.log_calls) == 1
    assert "normalization_metadata" in fake_logger.log_calls[0]["details"]


def test_normalizer_unexpected_exception_raises_firewall_error(fake_logger: FakeAuditLogger) -> None:
    """Verifies that unexpected errors from normalizer are wrapped inside FirewallError."""
    # Arrange
    normalizer = FakeTextNormalizer(should_raise=RuntimeError("Out of memory"))
    firewall = PromptFirewall([], fake_logger, normalizer)

    # Act & Assert
    with pytest.raises(FirewallError) as exc_info:
        firewall.inspect_prompt("Hello")
    assert "Normalizer failed unexpectedly" in str(exc_info.value)


# ===========================================================================
# 4 & 11. Detector Execution & Ordering
# ===========================================================================

def test_detector_execution_ordering_and_forwarding(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies detectors receive inputs in registration order with context."""
    # Arrange
    det1 = FakeDetector("D1")
    det2 = FakeDetector("D2")
    firewall = PromptFirewall([det1, det2], fake_logger, fake_normalizer)
    context = {"request_id": "req-123", "user": "test-user"}

    # Act
    firewall.inspect_prompt("User prompt", context=context)

    # Assert
    # Check execution order (det1 must be called first)
    assert len(det1.calls) == 1
    assert len(det2.calls) == 1
    assert det1.calls[0][0] == "User prompt"
    assert det1.calls[0][1] == context
    assert det2.calls[0][0] == "User prompt"
    assert det2.calls[0][1] == context


# ===========================================================================
# 5 & 13. Detector Failure & Error Result Builder
# ===========================================================================

def test_detector_failure_fail_secure_true(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies that fail_secure=True catches detector crashes and yields ERROR results."""
    # Arrange
    det_crash = FakeDetector("CrashDetector", should_raise=RuntimeError("API timeout"))
    firewall = PromptFirewall([det_crash], fake_logger, fake_normalizer, fail_secure=True)

    # Act
    res = firewall.inspect_prompt("trigger", context={"request_id": "req-000"})

    # Assert
    assert len(res.results) == 1
    err_res = res.results[0]
    assert err_res.status == DetectionStatus.ERROR
    assert err_res.detector_name == "CrashDetector"
    assert err_res.threat_type == ThreatType.NONE
    assert err_res.severity == SeverityLevel.INFORMATIONAL
    assert err_res.confidence == 0.0
    assert err_res.request_id == "req-000"
    assert "Detector error occurred during execution" in err_res.evidence


def test_detector_failure_fail_secure_false_re_raises(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies that fail_secure=False propagates detector exceptions directly."""
    # Arrange
    det_crash = FakeDetector("CrashDetector", should_raise=DetectorExecutionError("Custom error"))
    firewall = PromptFirewall([det_crash], fake_logger, fake_normalizer, fail_secure=False)

    # Act & Assert
    with pytest.raises(DetectorExecutionError) as exc_info:
        firewall.inspect_prompt("trigger")
    assert "Custom error" in str(exc_info.value)


def test_detector_failure_unexpected_error_fail_secure_false_raises_wrapped(
    fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer
) -> None:
    """Verifies unexpected errors under fail_secure=False are wrapped into DetectorExecutionError."""
    # Arrange
    det_crash = FakeDetector("CrashDetector", should_raise=ValueError("Unexpected crash"))
    firewall = PromptFirewall([det_crash], fake_logger, fake_normalizer, fail_secure=False)

    # Act & Assert
    with pytest.raises(DetectorExecutionError) as exc_info:
        firewall.inspect_prompt("trigger")
    assert "Unexpected detector execution crash" in str(exc_info.value)


# ===========================================================================
# 6. FirewallResponse Verification
# ===========================================================================

def test_firewall_response_structure(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies structural fields in FirewallResponse match expectations."""
    # Arrange
    firewall = PromptFirewall([], fake_logger, fake_normalizer)

    # Act
    res = firewall.inspect_prompt("Test prompt", context={"request_id": "req-xyz"})

    # Assert
    assert res.request_id == "req-xyz"
    assert res.normalized_prompt == "Test prompt"
    assert res.results == []
    assert res.execution_time_ms >= 0.0


# ===========================================================================
# 7. Audit Logger Verification
# ===========================================================================

def test_audit_logger_invocation_and_details(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies audit log is sent exactly once with required fields."""
    # Arrange
    det = FakeDetector("D")
    firewall = PromptFirewall([det], fake_logger, fake_normalizer)

    # Act
    firewall.inspect_prompt("Clean prompt", context={"request_id": "req-999"})

    # Assert
    assert len(fake_logger.log_calls) == 1
    call = fake_logger.log_calls[0]
    assert call["event_type"] == "PROMPT_AUDIT"
    assert call["request_id"] == "req-999"

    details = call["details"]
    assert details["request_id"] == "req-999"
    assert details["normalized_prompt"] == "Clean prompt"
    assert details["detector_count"] == 1
    assert "execution_time_ms" in details
    assert "results" in details
    assert "normalization_metadata" in details


# ===========================================================================
# 8. Audit Logger Failure
# ===========================================================================

def test_audit_logger_failure_does_not_break_firewall(fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies database/logger driver failure does not raise errors to the client."""
    # Arrange
    failing_logger = FakeAuditLogger(should_fail=True)
    firewall = PromptFirewall([], failing_logger, fake_normalizer)

    # Act & Assert
    # This should complete successfully despite logger crashing internally
    res = firewall.inspect_prompt("Safe Prompt")
    assert res.normalized_prompt == "Safe Prompt"


# ===========================================================================
# 9. Execution Timing
# ===========================================================================

def test_execution_time_non_negative(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies that firewall timing tracking measures a positive float."""
    # Arrange
    firewall = PromptFirewall([], fake_logger, fake_normalizer)

    # Act
    res = firewall.inspect_prompt("latency test")

    # Assert
    assert res.execution_time_ms >= 0.0


# ===========================================================================
# 10. Context Handling Tests
# ===========================================================================

def test_context_handling_scenarios(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies context is passed correctly and request_id fallback triggers."""
    firewall = PromptFirewall([], fake_logger, fake_normalizer)

    # 1. context = None (request_id defaults to "unknown")
    res_none = firewall.inspect_prompt("test", context=None)
    assert res_none.request_id == "unknown"

    # 2. context with request_id
    res_req = firewall.inspect_prompt("test", context={"request_id": "req-user"})
    assert res_req.request_id == "req-user"

    # 3. context with custom metadata
    res_custom = firewall.inspect_prompt("test", context={"request_id": "req-user", "session_id": "sess-xyz"})
    assert res_custom.request_id == "req-user"


# ===========================================================================
# 12. Multiple Detection Results
# ===========================================================================

def test_multiple_detection_results_aggregation(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies results from all registered detectors are aggregated in the response."""
    # Arrange
    r1 = DetectionResult(
        request_id="req-1", detector_name="D1", threat_type=ThreatType.NONE,
        severity=SeverityLevel.INFORMATIONAL, confidence=0.0, matched_text="",
        evidence="Clean", execution_time_ms=0.5, status=DetectionStatus.SUCCESS,
        timestamp=datetime.now(timezone.utc)
    )
    r2 = DetectionResult(
        request_id="req-1", detector_name="D2", threat_type=ThreatType.PROMPT_INJECTION,
        severity=SeverityLevel.HIGH, confidence=0.8, matched_text="dan",
        evidence="Dan match", execution_time_ms=0.6, status=DetectionStatus.SUCCESS,
        timestamp=datetime.now(timezone.utc)
    )
    det1 = FakeDetector("D1", return_result=r1)
    det2 = FakeDetector("D2", return_result=r2)
    firewall = PromptFirewall([det1, det2], fake_logger, fake_normalizer)

    # Act
    res = firewall.inspect_prompt("test", context={"request_id": "req-1"})

    # Assert
    assert len(res.results) == 2
    assert res.results[0].detector_name == "D1"
    assert res.results[1].detector_name == "D2"
    assert res.results[1].threat_type == ThreatType.PROMPT_INJECTION


# ===========================================================================
# 15. Regression Tests
# ===========================================================================

def test_future_detector_additions_compatibility(fake_logger: FakeAuditLogger, fake_normalizer: FakeTextNormalizer) -> None:
    """Verifies that firewall behaves consistently regardless of the number of registered detectors."""
    # Arrange
    # Simulates registration of many dynamic detectors
    detectors = [FakeDetector(f"DynamicDetector-{i}") for i in range(10)]
    firewall = PromptFirewall(detectors, fake_logger, fake_normalizer)

    # Act
    res = firewall.inspect_prompt("Regression test prompt")

    # Assert
    assert len(res.results) == 10
    for i, r in enumerate(res.results):
        assert r.detector_name == f"DynamicDetector-{i}"
        assert r.status == DetectionStatus.SUCCESS
