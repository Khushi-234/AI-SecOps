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
    Configuration settings for prompt hardening, sanitizers, and rule evaluation.
    """

    max_prompt_length: int = 10000
    enabled_sanitizers: tuple[str, ...] = ("injection", "secret", "pii")
    secret_mask_token: str = "[REDACTED]"
    pii_mask_token: str = "[REDACTED]"
    email_mask_token: str = "[REDACTED]"
    phone_mask_token: str = "[REDACTED]"
    sanitize_on_warn: bool = True
    append_constraints: bool = True
    raise_on_error: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates bounds and configurations."""
        if self.max_prompt_length <= 0:
            raise ConfigurationError(
                f"max_prompt_length must be positive, got {self.max_prompt_length}"
            )

        if not isinstance(self.enabled_sanitizers, tuple):
            object.__setattr__(
                self, "enabled_sanitizers", tuple(self.enabled_sanitizers)
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration to dictionary."""
        return {
            "max_prompt_length": self.max_prompt_length,
            "enabled_sanitizers": list(self.enabled_sanitizers),
            "secret_mask_token": self.secret_mask_token,
            "pii_mask_token": self.pii_mask_token,
            "email_mask_token": self.email_mask_token,
            "phone_mask_token": self.phone_mask_token,
            "sanitize_on_warn": self.sanitize_on_warn,
            "append_constraints": self.append_constraints,
            "raise_on_error": self.raise_on_error,
            "metadata": dict(self.metadata),
        }


DEFAULT_HARDENER_CONFIG = HardenerConfig()

__all__ = ["HardenerConfig", "DEFAULT_HARDENER_CONFIG"]
