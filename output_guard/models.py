"""
Data Transfer Objects (DTOs) and models for the Output Guard module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from output_guard.enums import (
    FindingType,
    OutputAction,
    OutputSeverity,
    SanitizationType,
)


@dataclass(slots=True, frozen=True)
class OutputFinding:
    """
    Typed security finding payload produced by an Output Guard detector.

    Attributes:
        detector_name: Name of the detector emitting the finding (e.g. 'SecretDetector').
        finding_type: Category of issue detected (FindingType or string).
        severity: Severity level (OutputSeverity or string).
        confidence: Confidence score from 0.0 to 1.0.
        matches: Tuple of matched text snippets or indicators.
        description: Human-readable finding summary.
        metadata: Contextual metric details.
        timestamp: Timezone-aware UTC timestamp.
    """

    detector_name: str
    finding_type: FindingType | str
    severity: OutputSeverity | str = OutputSeverity.MEDIUM
    confidence: float = 0.95
    matches: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Normalizes enums, strings, and tuple structures."""
        ftype_val = (
            self.finding_type.value
            if isinstance(self.finding_type, Enum)
            else str(self.finding_type)
        )
        object.__setattr__(self, "finding_type", ftype_val)

        sev_val = (
            self.severity.value
            if isinstance(self.severity, Enum)
            else str(self.severity)
        )
        object.__setattr__(self, "severity", sev_val)

        if not isinstance(self.matches, tuple):
            object.__setattr__(self, "matches", tuple(self.matches))

    def to_dict(self) -> dict[str, Any]:
        """Serializes OutputFinding to dictionary format."""
        return {
            "detector_name": self.detector_name,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "matches": list(self.matches),
            "description": self.description,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }



@dataclass(slots=True, frozen=True)
class SanitizationResult:

    """
    Result payload produced by an individual sanitizer.

    Attributes:
        sanitizer_name: Name/identifier of the sanitizer (e.g. 'SecretSanitizer').
        sanitization_type: The category of sanitization (e.g. SanitizationType.SECRET).
        is_modified: True if the output text was altered, False otherwise.
        original_output: Output text received by this sanitizer.
        sanitized_output: Transformed output text after sanitization.
        changes: Detailed list of modifications or replacements made.
        detected_issues: List of detected unsafe items or issue descriptions.
        execution_time_ms: Sanitizer execution duration in milliseconds.
        metadata: Additional contextual key-value metrics.
    """

    sanitizer_name: str
    sanitization_type: SanitizationType | str
    is_modified: bool
    original_output: str = ""
    sanitized_output: str = ""
    changes: list[dict[str, Any]] = field(default_factory=list)
    detected_issues: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensures enum values and mutable types are correctly normalized."""
        stype = (
            self.sanitization_type.value
            if isinstance(self.sanitization_type, Enum)
            else str(self.sanitization_type)
        )
        object.__setattr__(self, "sanitization_type", stype)

        if not isinstance(self.changes, list):
            object.__setattr__(self, "changes", list(self.changes))

        if not isinstance(self.detected_issues, list):
            object.__setattr__(self, "detected_issues", list(self.detected_issues))

    @property
    def modified(self) -> bool:
        """Alias for is_modified."""
        return self.is_modified

    def to_dict(self) -> dict[str, Any]:
        """Serializes SanitizationResult to a dictionary payload."""
        return {
            "sanitizer_name": self.sanitizer_name,
            "sanitization_type": self.sanitization_type,
            "is_modified": self.is_modified,
            "original_output": self.original_output,
            "sanitized_output": self.sanitized_output,
            "changes": self.changes,
            "detected_issues": self.detected_issues,
            "execution_time_ms": self.execution_time_ms,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class OutputSanitizationResult:
    """
    Final composite result payload produced by the Output Guard pipeline.

    Attributes:
        original_output: The raw response generated by the LLM.
        sanitized_output: The final sanitized output safe for the user.
        modified: True if any sanitizer modified the output response.
        applied_sanitizers: List of sanitizer names that altered the output.
        detected_issues: List of all issues detected across all sanitizers.
        action_taken: Output policy action (ALLOW, SANITIZE, BLOCK, WARN).
        execution_time_ms: Total pipeline execution time in milliseconds.
        metadata: Aggregated metadata and individual step details.
        timestamp: Timezone-aware UTC timestamp of execution.
    """

    original_output: str
    sanitized_output: str
    modified: bool
    applied_sanitizers: list[str] = field(default_factory=list)
    detected_issues: list[str] = field(default_factory=list)
    action_taken: OutputAction | str = OutputAction.ALLOW
    execution_time_ms: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Normalizes action taken and ensures clean list structures."""
        action_val = (
            self.action_taken.value
            if isinstance(self.action_taken, Enum)
            else str(self.action_taken)
        )
        object.__setattr__(self, "action_taken", action_val)

        if not isinstance(self.applied_sanitizers, list):
            object.__setattr__(self, "applied_sanitizers", list(self.applied_sanitizers))

        if not isinstance(self.detected_issues, list):
            object.__setattr__(self, "detected_issues", list(self.detected_issues))

    def to_dict(self) -> dict[str, Any]:
        """Serializes OutputSanitizationResult to a dictionary payload."""
        return {
            "original_output": self.original_output,
            "sanitized_output": self.sanitized_output,
            "modified": self.modified,
            "applied_sanitizers": self.applied_sanitizers,
            "detected_issues": self.detected_issues,
            "action_taken": self.action_taken,
            "execution_time_ms": self.execution_time_ms,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


__all__ = ["OutputFinding", "SanitizationResult", "OutputSanitizationResult"]

