"""
Pytest configuration and shared fixtures for the LLM test suite.

Contains reusable test double components (FakeAuditLogger, FakeDetector, FakeTextNormalizer)
and shared fixtures to ensure a DRY, modular test architecture.
"""

from datetime import datetime, timezone
from typing import Any
import pytest

from security.audit_logger import AuditLogger
from security.base_detector import BaseDetector
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.models import DetectionResult, NormalizationMetadata, NormalizationResult
from security.normalizer import TextNormalizer


# ===========================================================================
# Reusable Test Double Classes
# ===========================================================================

class FakeAuditLogger(AuditLogger):
    """Fake logger recording invocation call details."""

    def __init__(self, should_fail: bool = False) -> None:
        self.log_calls = []
        self.should_fail = should_fail

    def log_event(self, event_type: str, request_id: str, details: dict[str, Any]) -> None:
        if self.should_fail:
            raise RuntimeError("Database connection down")
        self.log_calls.append({
            "event_type": event_type,
            "request_id": request_id,
            "details": details
        })


class FakeDetector(BaseDetector):
    """Fake detector returning configurable mock outputs or exceptions."""

    @property
    def detector_name(self) -> str:
        return self._name

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.PROMPT_INJECTION

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.HIGH

    def __init__(
        self,
        name: str = "FakeDetector",
        should_raise: Exception | None = None,
        return_result: DetectionResult | None = None
    ) -> None:
        self._name = name
        self.should_raise = should_raise
        self.return_result = return_result
        self.calls = []

    def detect(self, prompt: str, context: dict[str, Any] | None = None) -> DetectionResult:
        self.calls.append((prompt, context))
        if self.should_raise:
            raise self.should_raise
        if self.return_result:
            return self.return_result
        return DetectionResult(
            request_id=context.get("request_id", "unknown") if context else "unknown",
            detector_name=self._name,
            threat_type=ThreatType.NONE,
            severity=SeverityLevel.INFORMATIONAL,
            confidence=0.0,
            matched_text="",
            evidence="Clean",
            execution_time_ms=0.5,
            status=DetectionStatus.SUCCESS,
            timestamp=datetime.now(timezone.utc)
        )


class FakeTextNormalizer(TextNormalizer):
    """Fake normalizer returning configurable cleaned text or errors."""

    def __init__(self, should_raise: Exception | None = None, return_text: str | None = None) -> None:
        self.should_raise = should_raise
        self.return_text = return_text
        self.calls = []

    def normalize_text(self, text: str) -> NormalizationResult:
        self.calls.append(text)
        if self.should_raise:
            raise self.should_raise
        norm_text = self.return_text if self.return_text is not None else text
        metadata = NormalizationMetadata(
            characters_removed=0,
            unicode_changes=0,
            control_characters_removed=0,
            processing_time_ms=0.1
        )
        return NormalizationResult(normalized_text=norm_text, metadata=metadata)


# ===========================================================================
# Reusable Pytest Fixtures
# ===========================================================================

@pytest.fixture
def fake_logger() -> FakeAuditLogger:
    """Provides a fresh instance of the fake audit logger."""
    return FakeAuditLogger()


@pytest.fixture
def fake_normalizer() -> FakeTextNormalizer:
    """Provides a fresh instance of the fake text normalizer."""
    return FakeTextNormalizer()


@pytest.fixture
def default_context() -> dict[str, Any]:
    """Provides a standard context dictionary with request_id."""
    return {"request_id": "test-request-id", "user_role": "user"}
