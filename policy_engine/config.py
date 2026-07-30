"""
Configuration Models for the Policy Engine.

Defines threshold settings, sanitization feature flags, and global engine parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from policy_engine.actions import PolicyAction
from policy_engine.exceptions import PolicyConfigurationError


@dataclass(slots=True, frozen=True)
class ThresholdConfig:
    """
    Risk score boundary thresholds governing Policy Engine decisions.

    Attributes:
        block_score_threshold: Composite score at/above which requests are BLOCKED (default: 0.75).
        sanitize_score_threshold: Composite score at/above which sanitizable findings trigger SANITIZE (default: 0.40).
        warn_score_threshold: Composite score at/above which requests trigger WARN monitoring (default: 0.25).
    """

    block_score_threshold: float = 0.75
    sanitize_score_threshold: float = 0.40
    warn_score_threshold: float = 0.25

    def __post_init__(self) -> None:
        """Validates threshold monotonicity and boundaries."""
        for name, val in [
            ("block_score_threshold", self.block_score_threshold),
            ("sanitize_score_threshold", self.sanitize_score_threshold),
            ("warn_score_threshold", self.warn_score_threshold),
        ]:
            if not (0.0 <= val <= 1.0):
                raise PolicyConfigurationError(
                    f"Threshold '{name}' must be between 0.0 and 1.0, got {val}"
                )

        if not (self.warn_score_threshold <= self.sanitize_score_threshold <= self.block_score_threshold):
            raise PolicyConfigurationError(
                f"Invalid threshold ordering: warn ({self.warn_score_threshold}) <= "
                f"sanitize ({self.sanitize_score_threshold}) <= block ({self.block_score_threshold}) required."
            )


@dataclass(slots=True, frozen=True)
class SanitizationConfig:
    """
    Settings governing prompt sanitization behavior and placeholders.

    Attributes:
        enable_pii_sanitization: Flag to redact PII data (default: True).
        enable_secret_masking: Flag to redact credentials & tokens (default: True).
        enable_injection_stripping: Flag to strip prompt injection tokens (default: True).
        pii_placeholder: Masking string for PII findings.
        secret_placeholder: Masking string for secrets findings.
    """

    enable_pii_sanitization: bool = True
    enable_secret_masking: bool = True
    enable_injection_stripping: bool = True
    pii_placeholder: str = "[REDACTED_PII]"
    secret_placeholder: str = "[REDACTED_SECRET]"


@dataclass(slots=True, frozen=True)
class PolicyEngineConfig:
    """
    Master configuration object for the PolicyEngine facade.

    Attributes:
        thresholds: Risk score boundary configuration.
        sanitization: Sanitization pipeline settings.
        strict_fail_secure: If True, unhandled errors default to BLOCK (default: True).
        default_action: Fallback action when no rules match (default: PolicyAction.ALLOW).
    """

    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    sanitization: SanitizationConfig = field(default_factory=SanitizationConfig)
    strict_fail_secure: bool = True
    default_action: PolicyAction = PolicyAction.ALLOW

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration to dictionary."""
        return {
            "thresholds": {
                "block_score_threshold": self.thresholds.block_score_threshold,
                "sanitize_score_threshold": self.thresholds.sanitize_score_threshold,
                "warn_score_threshold": self.thresholds.warn_score_threshold,
            },
            "sanitization": {
                "enable_pii_sanitization": self.sanitization.enable_pii_sanitization,
                "enable_secret_masking": self.sanitization.enable_secret_masking,
                "enable_injection_stripping": self.sanitization.enable_injection_stripping,
                "pii_placeholder": self.sanitization.pii_placeholder,
                "secret_placeholder": self.sanitization.secret_placeholder,
            },
            "strict_fail_secure": self.strict_fail_secure,
            "default_action": self.default_action.value,
        }
