"""
Strongly-Typed Domain Enumerations for the Risk Engine — Sprint 7.

Serves as the single source of truth for all constant domain values, risk classification tiers,
strategy types, evidence severity ratings, and recommended policy actions.

Design Principles:
    - SOLID: Single responsibility for type-safe domain constants.
    - DRY: Encapsulated reflection and parsing helpers via `BaseStringEnum`.
    - Strong Typing: All enums inherit from `str` and `Enum` to ensure native string interoperability.
    - OWASP Alignment: Provides unambiguous, auditable domain tokens for SIEM and security governance.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Type, TypeVar

T = TypeVar("T", bound="BaseStringEnum")


class BaseStringEnum(str, Enum):
    """
    Abstract base string enumeration offering reusable reflection, validation, and parsing helpers.

    Inherits from `str` and `Enum` to ensure all member values evaluate directly as strings,
    enabling seamless serialization, comparisons, and zero magic-string overhead.
    """

    @classmethod
    def values(cls) -> list[str]:
        """Returns a list of all raw string values defined for this enum."""
        return [item.value for item in cls]

    @classmethod
    def has_value(cls, value: str | Any) -> bool:
        """Checks whether a given string value matches any member value in this enum."""
        if not isinstance(value, str):
            return False
        return value in cls.values()

    @classmethod
    def from_string(cls: Type[T], value: str) -> T:
        """
        Parses a raw string into its corresponding enum member instance.

        Args:
            value: Raw string to be converted into an enum member.

        Returns:
            The matching enum member instance.

        Raises:
            ValueError: If the string value does not match any valid enum member.
        """
        for member in cls:
            if member.value == value:
                return member
        raise ValueError(
            f"Invalid {cls.__name__} value: '{value}'. Valid choices are: {cls.values()}"
        )


# ===========================================================================
# Domain Enumerations
# ===========================================================================


class RiskLevel(BaseStringEnum):
    """
    Represents the final classified risk level assigned to a request payload.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScoringStrategy(BaseStringEnum):
    """
    Represents available risk scoring algorithms within the engine.
    """

    WEIGHTED = "WEIGHTED"
    THRESHOLD = "THRESHOLD"
    ADAPTIVE = "ADAPTIVE"
    COMPOSITE = "COMPOSITE"


class AggregationStrategy(BaseStringEnum):
    """
    Represents evidence aggregation strategies for merging multi-module security findings.
    """

    WEIGHTED_SUM = "WEIGHTED_SUM"
    MAX_SCORE = "MAX_SCORE"
    AVERAGE = "AVERAGE"
    CONSERVATIVE = "CONSERVATIVE"
    HYBRID = "HYBRID"


class ConfidenceStrategy(BaseStringEnum):
    """
    Represents mathematical confidence calculation strategies.
    """

    WEIGHTED = "WEIGHTED"
    CONSENSUS = "CONSENSUS"
    HISTORICAL = "HISTORICAL"
    HYBRID = "HYBRID"


class RecommendedAction(BaseStringEnum):
    """
    Represents actions recommended to the Policy Engine downstream.
    """

    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    ALLOW_WITH_WARNING = "ALLOW_WITH_WARNING"
    MONITOR = "MONITOR"
    SANITIZE_RECOMMENDED = "SANITIZE_RECOMMENDED"
    REVIEW = "REVIEW"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class EvidenceSource(BaseStringEnum):
    """
    Represents upstream security evidence providers across the pipeline.
    """

    PROMPT_FIREWALL = "PROMPT_FIREWALL"
    INPUT_VALIDATOR = "INPUT_VALIDATOR"
    RISK_ENGINE = "RISK_ENGINE"
    FUTURE_MODULE = "FUTURE_MODULE"


class FindingSeverity(BaseStringEnum):
    """
    Represents finding severity ratings assigned by detectors and validators.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MergeStrategy(BaseStringEnum):
    """
    Represents evidence merging and conflict resolution behavior.
    """

    FIRST_MATCH = "FIRST_MATCH"
    HIGHEST_SCORE = "HIGHEST_SCORE"
    MERGE_ALL = "MERGE_ALL"
    DEDUPLICATE = "DEDUPLICATE"


class FailSafeMode(BaseStringEnum):
    """
    Represents engine failure behavior on unexpected errors or missing upstream data.
    """

    FAIL_OPEN = "FAIL_OPEN"
    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_SECURE = "FAIL_SECURE"
