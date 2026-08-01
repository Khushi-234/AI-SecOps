"""
Data Transfer Objects (DTOs) for the Prompt Hardener module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from prompt_hardener.enums import HardeningAction


@dataclass(slots=True, frozen=True)
class HardeningResult:
    """
    Final result payload produced by the Prompt Hardener.

    Attributes:
        original_prompt: The initial draft prompt supplied before hardening.
        hardened_prompt: The hardened prompt payload ready for PromptBuilder.
        action_taken: Policy action evaluated ('ALLOW', 'WARN', 'SANITIZE', 'BLOCK').
        applied_injectors: Tuple of injector identifiers that enhanced the prompt.
        added_constraints: Tuple of security constraints injected into the prompt.
        modified: True if prompt content or constraints were changed, False otherwise.
        metadata: Execution metadata, metrics, and timestamps.
        timestamp: Timezone-aware UTC timestamp.
    """

    original_prompt: str
    hardened_prompt: str
    action_taken: HardeningAction | str
    applied_injectors: tuple[str, ...] = field(default_factory=tuple)
    added_constraints: tuple[str, ...] = field(default_factory=tuple)
    modified: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validates actions and converts sequences to immutable tuples."""
        action_val = (
            self.action_taken.value
            if isinstance(self.action_taken, Enum)
            else str(self.action_taken)
        )
        object.__setattr__(self, "action_taken", action_val)

        if not isinstance(self.applied_injectors, tuple):
            object.__setattr__(
                self, "applied_injectors", tuple(self.applied_injectors)
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
            "applied_injectors": list(self.applied_injectors),
            "added_constraints": list(self.added_constraints),
            "modified": self.modified,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


__all__ = ["HardeningResult"]
