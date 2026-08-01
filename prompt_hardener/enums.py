"""
Enumerations for the Prompt Hardener module.
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
    Matches PolicyAction values emitted by Policy Engine.
    """

    ALLOW = "ALLOW"
    WARN = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class HardeningConstraintType(BaseStringEnum):
    """
    Categories of security constraints injected into prompts.
    """

    PROMPT_INJECTION = "PROMPT_INJECTION"
    SECRET_LEAK = "SECRET_LEAK"
    PII_LEAK = "PII_LEAK"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    TOOL_USAGE = "TOOL_USAGE"


__all__ = ["BaseStringEnum", "HardeningAction", "HardeningConstraintType"]
