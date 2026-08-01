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


DEFAULT_CRITICAL_THREATS: tuple[str, ...] = (
    "credential_leak",
    "secret_exposure",
    "system_prompt_extraction",
    "severe_jailbreak",
    "prompt_injection",
    "jailbreak",
    "secret_leak",
    "pii_leak",
)


@dataclass(slots=True, frozen=True)
class PolicyEngineConfig:
    """
    Master configuration object for the PolicyEngine facade.

    Attributes:
        thresholds: Risk score boundary configuration.
        critical_threats: Tuple of critical threat names that trigger immediate BLOCK decision.
        strict_fail_secure: If True, unhandled errors default to BLOCK (default: True).
        default_action: Fallback action when no rules match (default: PolicyAction.WARN).
    """

    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    critical_threats: tuple[str, ...] = field(default_factory=lambda: DEFAULT_CRITICAL_THREATS)
    strict_fail_secure: bool = True
    default_action: PolicyAction = PolicyAction.WARN

    def __post_init__(self) -> None:
        """Converts critical_threats list to immutable tuple if needed."""
        if not isinstance(self.critical_threats, tuple):
            object.__setattr__(self, "critical_threats", tuple(self.critical_threats))

    def to_dict(self) -> dict[str, Any]:
        """Serializes configuration to dictionary."""
        return {
            "thresholds": {
                "block_score_threshold": self.thresholds.block_score_threshold,
                "sanitize_score_threshold": self.thresholds.sanitize_score_threshold,
                "warn_score_threshold": self.thresholds.warn_score_threshold,
            },
            "critical_threats": list(self.critical_threats),
            "strict_fail_secure": self.strict_fail_secure,
            "default_action": (
                self.default_action.value
                if hasattr(self.default_action, "value")
                else str(self.default_action)
            ),
        }

