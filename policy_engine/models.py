"""
Immutable Domain Data Models for the Policy Engine.

Defines canonical Data Transfer Objects (DTOs) for Policy Engine decision contexts,
sanitization tracking, and policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.enums import SanitizationType
from policy_engine.exceptions import InvalidPolicyInputError


@dataclass(slots=True, frozen=True)
class SanitizationEdit:
    """
    Represents a single atomic text modification/redaction applied during sanitization.

    Attributes:
        edit_id: Unique string identifier for the edit.
        sanitization_type: Type of sanitization performed (PII, secret, injection, tag).
        original_text: The original unsafe text segment that was replaced.
        replacement_text: The redacted or substituted text string.
        start_char: Starting character index in original prompt.
        end_char: Ending character index in original prompt.
    """

    edit_id: str
    sanitization_type: SanitizationType | str
    original_text: str
    replacement_text: str
    start_char: int
    end_char: int

    def __post_init__(self) -> None:
        """Validates character offsets."""
        if self.start_char < 0 or self.end_char < 0 or self.end_char < self.start_char:
            raise InvalidPolicyInputError(
                f"Invalid character range [{self.start_char}, {self.end_char}] for edit '{self.edit_id}'."
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes edit details to dictionary."""
        return {
            "edit_id": self.edit_id,
            "sanitization_type": (
                self.sanitization_type.value
                if isinstance(self.sanitization_type, Enum)
                else str(self.sanitization_type)
            ),
            "original_text": self.original_text,
            "replacement_text": self.replacement_text,
            "start_char": self.start_char,
            "end_char": self.end_char,
        }


@dataclass(slots=True, frozen=True)
class SanitizationResult:
    """
    Aggregate output container returned by the Sanitization Pipeline.

    Attributes:
        sanitized_prompt: The resulting clean prompt text.
        edits: Sequence of applied SanitizationEdit records.
        processing_time_ms: Pipeline execution duration in milliseconds.
    """

    sanitized_prompt: str
    edits: tuple[SanitizationEdit, ...] = field(default_factory=tuple)
    processing_time_ms: float = 0.0

    def __post_init__(self) -> None:
        """Validates non-negative processing time and tuple sequence."""
        if self.processing_time_ms < 0.0:
            raise InvalidPolicyInputError("processing_time_ms cannot be negative.")
        if not isinstance(self.edits, tuple):
            object.__setattr__(self, "edits", tuple(self.edits))

    def to_dict(self) -> dict[str, Any]:
        """Serializes result to dictionary."""
        return {
            "sanitized_prompt": self.sanitized_prompt,
            "edits": [edit.to_dict() for edit in self.edits],
            "processing_time_ms": self.processing_time_ms,
        }


@dataclass(slots=True, frozen=True)
class PolicyDecision:
    """
    Canonical decision payload produced by the Policy Engine.

    Required Fields:
        action: PolicyAction enum ('ALLOW', 'WARN', 'SANITIZE', 'BLOCK').
        reason: Rationale justifying the decision.
        risk_score: Risk score evaluated [0-100 or 0.0-1.0].
        rule_triggered: Name of the rule triggering this decision.
        timestamp: Timezone-aware UTC timestamp.
        metadata: Diagnostic and execution metadata.

    Enforcement Output Fields:
        is_approved: True for ALLOW, WARN, SANITIZE; False for BLOCK.
        final_prompt: Approved or Sanitized prompt string, or None if BLOCKED.
        applied_sanitizations: Tuple of SanitizationEdit records applied.
        request_id: Optional request identifier for correlation.
    """

    action: PolicyAction | str
    reason: str
    risk_score: float = 0.0
    rule_triggered: str = "DEFAULT_RULE"
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # Enforcement details
    is_approved: bool = True
    final_prompt: str | None = None
    applied_sanitizations: tuple[SanitizationEdit, ...] = field(default_factory=tuple)
    request_id: str = ""

    def __post_init__(self) -> None:
        """Validates decision consistency and field types."""
        action_obj = (
            PolicyAction.from_string(self.action)
            if isinstance(self.action, str) and PolicyAction.has_value(self.action)
            else self.action
        )
        object.__setattr__(self, "action", action_obj)

        if not isinstance(self.applied_sanitizations, tuple):
            object.__setattr__(
                self, "applied_sanitizations", tuple(self.applied_sanitizations)
            )

        # Enforce is_approved consistency based on action if not explicitly overridden
        action_val = self.action.value if isinstance(self.action, Enum) else str(self.action)
        if action_val == PolicyAction.BLOCK.value:
            object.__setattr__(self, "is_approved", False)
            object.__setattr__(self, "final_prompt", None)

    def to_dict(self) -> dict[str, Any]:
        """Serializes PolicyDecision to standard dictionary payload."""
        return {
            "request_id": self.request_id,
            "action": (
                self.action.value if isinstance(self.action, Enum) else str(self.action)
            ),
            "reason": self.reason,
            "risk_score": self.risk_score,
            "rule_triggered": self.rule_triggered,
            "is_approved": self.is_approved,
            "final_prompt": self.final_prompt,
            "applied_sanitizations": [
                edit.to_dict() for edit in self.applied_sanitizations
            ],
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }
