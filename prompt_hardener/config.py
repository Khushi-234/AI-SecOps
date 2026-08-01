"""
Configuration models and defaults for the Prompt Hardener module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from prompt_hardener.exceptions import ConfigurationError


@dataclass(slots=True, frozen=True)
class HardenerConfig:
    """
    Configuration settings for prompt hardening, rule evaluation, and injectors.
    """

    max_prompt_length: int = 10000
    inject_system_defenses: bool = True
    inject_security_constraints: bool = True
    inject_defensive_instructions: bool = True
    append_constraints: bool = True
    raise_on_error: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates bounds and configurations."""
        if self.max_prompt_length <= 0:
            raise ConfigurationError(
                f"max_prompt_length must be positive, got {self.max_prompt_length}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration to dictionary."""
        return {
            "max_prompt_length": self.max_prompt_length,
            "inject_system_defenses": self.inject_system_defenses,
            "inject_security_constraints": self.inject_security_constraints,
            "inject_defensive_instructions": self.inject_defensive_instructions,
            "append_constraints": self.append_constraints,
            "raise_on_error": self.raise_on_error,
            "metadata": dict(self.metadata),
        }


DEFAULT_HARDENER_CONFIG = HardenerConfig()

__all__ = ["HardenerConfig", "DEFAULT_HARDENER_CONFIG"]
