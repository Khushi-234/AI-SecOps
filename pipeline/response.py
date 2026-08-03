"""
PipelineResponse DTO and PipelineStatus Enum for AI-SecOps Framework execution results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class PipelineStatus(str, Enum):
    """Execution status enum for AISecOpsPipeline."""

    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    FAIL_SECURE_BLOCKED = "FAIL_SECURE_BLOCKED"
    ERROR = "ERROR"


@dataclass(slots=True, frozen=True)
class PipelineResponse:
    """
    Final composite response object returned by AISecOpsPipeline.execute().

    Attributes:
        request_id: Correlation identifier matching the request.
        status: Execution status (PipelineStatus).
        success: True if pipeline completed safely without security block or crash.
        blocked: True if pipeline was blocked by any guardrail or fail-secure trigger.
        blocked_by: Name of the component that triggered the block (if blocked).
        output_text: Final safe response text to display to user.
        risk_score: Normalized risk score (0.0 to 1.0) from Risk Engine.
        risk_level: Assigned risk level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        warnings: List of non-fatal warnings accumulated during execution.
        applied_hardening: Applied prompt hardening actions/constraints.
        applied_sanitization: Applied output sanitization details.
        total_execution_time_ms: Total end-to-end wall-clock time in milliseconds.
        stage_timings_ms: Execution duration breakdown by pipeline stage.
        metadata: Aggregated execution telemetry and module findings.
        timestamp: Timezone-aware UTC completion timestamp.
    """

    request_id: str
    status: PipelineStatus | str = PipelineStatus.SUCCESS
    success: bool = True
    blocked: bool = False
    blocked_by: Optional[str] = None
    output_text: str = ""
    risk_score: float = 0.0
    risk_level: str = "LOW"
    warnings: List[str] = field(default_factory=list)
    applied_hardening: List[str] = field(default_factory=list)
    applied_sanitization: List[str] = field(default_factory=list)
    total_execution_time_ms: float = 0.0
    stage_timings_ms: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Normalizes status enum and immutable list fields."""
        status_val = (
            self.status.value if isinstance(self.status, Enum) else str(self.status)
        )
        object.__setattr__(self, "status", status_val)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes response to dictionary representation."""
        return {
            "request_id": self.request_id,
            "status": self.status,
            "success": self.success,
            "blocked": self.blocked,
            "blocked_by": self.blocked_by,
            "output_text": self.output_text,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "warnings": self.warnings,
            "applied_hardening": self.applied_hardening,
            "applied_sanitization": self.applied_sanitization,
            "total_execution_time_ms": self.total_execution_time_ms,
            "stage_timings_ms": self.stage_timings_ms,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }
