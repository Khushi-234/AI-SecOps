"""
Strongly-Typed Domain Enumerations for the Policy Engine.

Re-exports PolicyAction from actions.py for backward compatibility and defines SanitizationType.
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
        return value in cls.values()

    @classmethod
    def from_string(cls: Type[T], value: str) -> T:
        for member in cls:
            if member.value == value.upper():
                return member
        raise ValueError(
            f"Invalid {cls.__name__} value: '{value}'. Valid choices are: {cls.values()}"
        )


def __getattr__(name: str) -> Any:
    if name in ("ACTION_PRIORITY", "PolicyAction"):
        from policy_engine import actions
        return getattr(actions, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ACTION_PRIORITY", "PolicyAction", "BaseStringEnum"]

