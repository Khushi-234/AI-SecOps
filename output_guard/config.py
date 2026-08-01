"""
Configuration models and default constants for the Output Guard module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from output_guard.enums import PromptLeakMode
from output_guard.exceptions import ConfigurationError

# Default replacement values
SECRET_REPLACEMENT: str = "[REDACTED_SECRET]"
PII_REPLACEMENT: str = "[REDACTED_PII]"
PROMPT_LEAK_REPLACEMENT: str = "[SYSTEM_INFORMATION_REMOVED]"
TOXIC_REPLACEMENT: str = "[CONTENT_REMOVED_DUE_TO_SAFETY_POLICY]"


@dataclass(slots=True, frozen=True)
class OutputGuardConfig:
    """
    Configuration settings for Output Guard, its detectors, and sanitizers.
    """

    enabled_sanitizers: tuple[str, ...] = (
        "prompt_leak",
        "secret",
        "pii",
        "unsafe",
        "toxic",
    )
    pipeline_order: tuple[str, ...] = (
        "prompt_leak",
        "secret",
        "pii",
        "unsafe",
        "toxic",
    )
    max_output_length: int = 50000
    secret_replacement: str = SECRET_REPLACEMENT
    pii_replacement: str = PII_REPLACEMENT
    prompt_leak_replacement: str = PROMPT_LEAK_REPLACEMENT
    toxic_replacement: str = TOXIC_REPLACEMENT
    unsafe_output_replacement: str = "[REDACTED_UNSAFE_COMMAND]"

    # Fine-grained PII replacements
    email_replacement: str = PII_REPLACEMENT
    phone_replacement: str = PII_REPLACEMENT
    ip_replacement: str = PII_REPLACEMENT
    ssn_replacement: str = PII_REPLACEMENT
    credit_card_replacement: str = PII_REPLACEMENT

    # Detector confidence scores
    confidence_secret: float = 0.98
    confidence_prompt_leak: float = 0.95
    confidence_unsafe: float = 0.95
    confidence_pii: float = 0.90
    confidence_policy_violation: float = 0.85
    confidence_toxic: float = 0.80

    # Version metadata
    framework_version: str = "1.0.0"
    module_version: str = "1.0.0"
    pipeline_version: str = "1.0.0"

    # Control behavior & modes
    fail_secure: bool = True
    prompt_leak_mode: PromptLeakMode | str = PromptLeakMode.MASK
    raise_on_error: bool = False
    truncate_exceeding_output: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates configuration parameters and normalizes enums."""
        if self.max_output_length <= 0:
            raise ConfigurationError(
                f"max_output_length must be positive, got {self.max_output_length}"
            )

        plmode = (
            self.prompt_leak_mode.value
            if isinstance(self.prompt_leak_mode, PromptLeakMode)
            else str(self.prompt_leak_mode)
        )
        object.__setattr__(self, "prompt_leak_mode", PromptLeakMode(plmode) if PromptLeakMode.has_value(plmode) else plmode)


        if not isinstance(self.enabled_sanitizers, tuple):
            object.__setattr__(
                self, "enabled_sanitizers", tuple(self.enabled_sanitizers)
            )

    def is_sanitizer_enabled(self, sanitizer_name: str) -> bool:
        """Checks if a specific sanitizer is enabled in the configuration."""
        clean_name = (
            sanitizer_name.lower()
            .replace("outputsanitizer", "")
            .replace("sanitizer", "")
            .replace("output", "")
            .replace("_", "")
            .replace("-", "")
            .strip()
        )
        for enabled in self.enabled_sanitizers:
            clean_enabled = (
                enabled.lower()
                .replace("outputsanitizer", "")
                .replace("sanitizer", "")
                .replace("output", "")
                .replace("_", "")
                .replace("-", "")
                .strip()
            )
            if clean_enabled == clean_name:
                return True
        return False


    def to_dict(self) -> dict[str, Any]:
        """Serializes OutputGuardConfig to dictionary."""
        return {
            "enabled_sanitizers": list(self.enabled_sanitizers),
            "max_output_length": self.max_output_length,
            "secret_replacement": self.secret_replacement,
            "pii_replacement": self.pii_replacement,
            "prompt_leak_replacement": self.prompt_leak_replacement,
            "toxic_replacement": self.toxic_replacement,
            "raise_on_error": self.raise_on_error,
            "truncate_exceeding_output": self.truncate_exceeding_output,
            "metadata": dict(self.metadata),
        }


DEFAULT_OUTPUT_GUARD_CONFIG = OutputGuardConfig()

__all__ = [
    "SECRET_REPLACEMENT",
    "PII_REPLACEMENT",
    "PROMPT_LEAK_REPLACEMENT",
    "TOXIC_REPLACEMENT",
    "OutputGuardConfig",
    "DEFAULT_OUTPUT_GUARD_CONFIG",
]
