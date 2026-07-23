from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from security.enums import DetectionStatus, SeverityLevel, ThreatType


@dataclass(slots=True)
class DetectionResult:
    """
    Data container holding the scanning results and metadata from a single detector.
    """

    request_id: str
    detector_name: str
    threat_type: ThreatType
    severity: SeverityLevel
    confidence: float
    matched_text: str
    evidence: str
    execution_time_ms: float
    status: DetectionStatus
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validate confidence boundaries
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

        # Validate execution time
        if self.execution_time_ms < 0.0:
            raise ValueError(
                f"execution_time_ms cannot be negative, got {self.execution_time_ms}"
            )

        # Validate timezone-aware datetime
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the DetectionResult instance to a standard Python dictionary.

        Converts enums to their raw string values and formats datetimes to ISO-8601.
        """
        return {
            "request_id": self.request_id,
            "detector_name": self.detector_name,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "matched_text": self.matched_text,
            "evidence": self.evidence,
            "metadata": dict(self.metadata),
            "execution_time_ms": self.execution_time_ms,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class FirewallResponse:
    """
    Aggregated response returned by the PromptFirewall containing all security scan findings.
    """

    request_id: str
    normalized_prompt: str
    execution_time_ms: float
    results: list[DetectionResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Validate execution time
        if self.execution_time_ms < 0.0:
            raise ValueError(
                f"execution_time_ms cannot be negative, got {self.execution_time_ms}"
            )

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the FirewallResponse and all nested DetectionResult items to a dictionary.
        """
        return {
            "request_id": self.request_id,
            "normalized_prompt": self.normalized_prompt,
            "results": [result.to_dict() for result in self.results],
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass(slots=True)
class NormalizationMetadata:
    """
    Trace statistics mapping character alterations applied during text normalization.
    """

    characters_removed: int
    unicode_changes: int
    control_characters_removed: int
    processing_time_ms: float

    def __post_init__(self) -> None:
        # Validate positive integers and floats
        if self.characters_removed < 0:
            raise ValueError(
                f"characters_removed cannot be negative, got {self.characters_removed}"
            )
        if self.unicode_changes < 0:
            raise ValueError(
                f"unicode_changes cannot be negative, got {self.unicode_changes}"
            )
        if self.control_characters_removed < 0:
            raise ValueError(
                f"control_characters_removed cannot be negative, got {self.control_characters_removed}"
            )
        if self.processing_time_ms < 0.0:
            raise ValueError(
                f"processing_time_ms cannot be negative, got {self.processing_time_ms}"
            )

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the NormalizationMetadata instance to a standard dictionary.
        """
        return {
            "characters_removed": self.characters_removed,
            "unicode_changes": self.unicode_changes,
            "control_characters_removed": self.control_characters_removed,
            "processing_time_ms": self.processing_time_ms,
        }


@dataclass(slots=True)
class NormalizationResult:
    """
    Result of a text normalization execution containing the clean text and change statistics.
    """

    normalized_text: str
    metadata: NormalizationMetadata

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the NormalizationResult instance and nested metadata to a dictionary.
        """
        return {
            "normalized_text": self.normalized_text,
            "metadata": self.metadata.to_dict(),
        }
