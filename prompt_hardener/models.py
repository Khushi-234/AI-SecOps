"""
Data Transfer Objects (DTOs) for the Prompt Hardener module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from prompt_hardener.enums import HardeningAction, SanitizationType


@dataclass(slots=True, frozen=True)
class SanitizationResult:
    """
    Result returned by individual sanitizers and the sanitizer pipeline.
    """

    original_text: str
    sanitized_text: str
    sanitizer_type: SanitizationType | str
    modified: bool = False
    replacements_count: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates fields and ensures string conversion if enum."""
        stype = (
            self.sanitizer_type.value
            if isinstance(self.sanitizer_type, Enum)
            else str(self.sanitizer_type)
        )
        object.__setattr__(self, "sanitizer_type", stype)

    def to_dict(self) -> dict[str, Any]:
        """Serializes SanitizationResult to dictionary."""
        return {
            "original_text": self.original_text,
            "sanitized_text": self.sanitized_text,
            "sanitizer_type": self.sanitizer_type,
            "modified": self.modified,
            "replacements_count": self.replacements_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class HardeningResult:
    """
    Final result payload produced by the Prompt Hardener.

    Attributes:
        original_prompt: The initial prompt supplied before hardening.
        hardened_prompt: The transformed prompt ready for PromptBuilder / LLM.
        action_taken: Policy / Hardening action ('ALLOW', 'WARN', 'SANITIZE', 'BLOCK').
        applied_sanitizers: Tuple of sanitizer identifiers that modified the prompt.
        added_constraints: Tuple of security constraints added to the prompt.
        modified: True if prompt content or constraints were changed, False otherwise.
        metadata: Execution metadata, metrics, and timestamps.
        timestamp: Timezone-aware UTC timestamp.
    """

    original_prompt: str
    hardened_prompt: str
    action_taken: HardeningAction | str
    applied_sanitizers: tuple[str, ...] = field(default_factory=tuple)
    added_constraints: tuple[str, ...] = field(default_factory=tuple)
    modified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validates actions and converts lists to immutable tuples."""
        action_val = (
            self.action_taken.value
            if isinstance(self.action_taken, Enum)
            else str(self.action_taken)
        )
        object.__setattr__(self, "action_taken", action_val)

        if not isinstance(self.applied_sanitizers, tuple):
            object.__setattr__(
                self, "applied_sanitizers", tuple(self.applied_sanitizers)
            )

        if not isinstance(self.added_constraints, tuple):
            object.__setattr__(
                self, "added_constraints", tuple(self.added_constraints)
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes HardeningResult to dictionary payload."""
        return {
            "original_prompt": self.original_prompt,
            "hardened_prompt": self.hardened_prompt,
            "action_taken": self.action_taken,
            "applied_sanitizers": list(self.applied_sanitizers),
            "added_constraints": list(self.added_constraints),
            "modified": self.modified,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


__all__ = ["SanitizationResult", "HardeningResult"]
