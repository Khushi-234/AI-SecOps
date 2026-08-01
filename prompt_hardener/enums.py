"""
Enumerations for the Prompt Hardener module.

Defines canonical actions and sanitization types for transforming user prompts.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Type, TypeVar

T = TypeVar("T", bound="BaseStringEnum")


class BaseStringEnum(str, Enum):
    """Abstract base string enumeration offering reusable reflection and parsing helpers."""

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]

    @classmethod
    def has_value(cls, value: str | Any) -> bool:
        if not isinstance(value, str):
            return False
        return value.upper() in [v.upper() for v in cls.values()]

    @classmethod
    def from_string(cls: Type[T], value: str) -> T:
        for member in cls:
            if member.value.upper() == value.strip().upper():
                return member
        raise ValueError(
            f"Invalid {cls.__name__} value: '{value}'. Valid choices are: {cls.values()}"
        )


class HardeningAction(BaseStringEnum):
    """
    Actions supported by the Prompt Hardener.
    Matches PolicyAction values.
    """

    ALLOW = "ALLOW"
    WARN = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class SanitizationType(BaseStringEnum):
    """
    Categories of sanitization performed by prompt sanitizers.
    """

    INJECTION = "INJECTION"
    SECRET = "SECRET"
    PII = "PII"
    RULE_CONSTRAINT = "RULE_CONSTRAINT"


__all__ = ["BaseStringEnum", "HardeningAction", "SanitizationType"]
