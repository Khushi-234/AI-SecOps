"""
Strongly-Typed Domain Enumerations for the Policy Engine.

Re-exports PolicyAction from actions.py for backward compatibility and defines SanitizationType.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Type, TypeVar

from policy_engine.actions import ACTION_PRIORITY, PolicyAction

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
        return value in cls.values()

    @classmethod
    def from_string(cls: Type[T], value: str) -> T:
        for member in cls:
            if member.value == value.upper():
                return member
        raise ValueError(
            f"Invalid {cls.__name__} value: '{value}'. Valid choices are: {cls.values()}"
        )


class SanitizationType(BaseStringEnum):
    """
    Categorizes the specific type of prompt sanitization performed.

    Members:
        PII_REDACTION: Redaction of Personally Identifiable Information.
        SECRET_MASKING: Masking of API keys, tokens, and sensitive secrets.
        INJECTION_STRIPPING: Removal of prompt injection delimiters and system override phrases.
        TAG_REMOVAL: Removal of unsafe HTML/XML control tags.
    """

    PII_REDACTION = "PII_REDACTION"
    SECRET_MASKING = "SECRET_MASKING"
    INJECTION_STRIPPING = "INJECTION_STRIPPING"
    TAG_REMOVAL = "TAG_REMOVAL"


__all__ = ["SanitizationType", "ACTION_PRIORITY", "BaseStringEnum"]
