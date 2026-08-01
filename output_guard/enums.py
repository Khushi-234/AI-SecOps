"""
Enumerations for the Output Guard module.

Defines canonical output actions and sanitization types for inspecting and
sanitizing LLM-generated outputs.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Type, TypeVar

T = TypeVar("T", bound="BaseStringEnum")


class BaseStringEnum(str, Enum):
    """Abstract base string enumeration offering reusable reflection and parsing helpers."""

    @classmethod
    def values(cls) -> list[str]:
        """Returns all enum string values."""
        return [item.value for item in cls]

    @classmethod
    def has_value(cls, value: str | Any) -> bool:
        """Checks if a given string matches any enum value (case-insensitive)."""
        if not isinstance(value, str):
            return False
        return value.upper() in [v.upper() for v in cls.values()]

    @classmethod
    def from_string(cls: Type[T], value: str) -> T:
        """Parses string into corresponding enum member (case-insensitive)."""
        for member in cls:
            if member.value.upper() == value.strip().upper():
                return member
        raise ValueError(
            f"Invalid {cls.__name__} value: '{value}'. Valid choices are: {cls.values()}"
        )


class SanitizationType(BaseStringEnum):
    """
    Categories of output sanitization handled by individual sanitizers.
    """

    SECRET = "SECRET"
    PII = "PII"
    PROMPT_LEAK = "PROMPT_LEAK"
    TOXIC_CONTENT = "TOXIC_CONTENT"
    UNSAFE_CODE = "UNSAFE_CODE"



class OutputAction(BaseStringEnum):
    """
    Actions supported by Output Guard policy evaluation logic.
    """

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    WARN = "WARN"


class PromptLeakMode(BaseStringEnum):

    """
    Sanitization strategies for handling detected system prompt leaks.
    """

    MASK = "MASK"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"
    BLOCK = "BLOCK"


class FindingType(BaseStringEnum):
    """
    Security finding categories for Output Guard detectors.
    """

    SECRET = "SECRET"
    PROMPT_LEAK = "PROMPT_LEAK"
    PII = "PII"
    TOXIC_CONTENT = "TOXIC_CONTENT"
    UNSAFE_CODE = "UNSAFE_CODE"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class OutputSeverity(BaseStringEnum):
    """
    Severity rating classification for Output Findings.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


__all__ = [
    "BaseStringEnum",
    "SanitizationType",
    "OutputAction",
    "PromptLeakMode",
    "FindingType",
    "OutputSeverity",
]

