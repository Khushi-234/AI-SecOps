"""
Risk Engine Utility Module — Sprint 7.

Enterprise-grade, stateless mathematical helper functions and sequence utilities.

Purpose
-------
Provides generic, stateless, side-effect-free helper functions for numerical score validation,
clamping, precision rounding, sequence flattening, and immutable tuple conversion across
the Risk Engine framework.

This module is strictly utility-focused:
- It contains **no** risk scoring algorithms.
- It contains **no** evidence aggregation logic.
- It contains **no** confidence evaluation calculations.
- It contains **no** policy decision rules.
- It contains **no** engine orchestration or I/O.

Responsibilities
----------------
1. Validate numeric float inputs for boundary compliance [0.0, 1.0], NaN, and Infinity.
2. Clamp risk scores and confidence ratings to configured bounds.
3. Apply standard decimal precision rounding (`DEFAULT_SCORE_PRECISION`).
4. Perform safe, recursive sequence flattening for heterogeneous findings.
5. Convert generic iterables into immutable tuples.

Design Principles
-----------------
- **Pure Functions**: Every function is deterministic, holding no global state and mutating no inputs.
- **Thread Safety**: Stateless design guarantees 100% thread safety across concurrent executions.
- **Fail-Secure**: Raises `InvalidRiskInputError` on malformed, NaN, or Infinite numbers.
- **Performance**: O(1) for scalar validations/clamping; O(N) linear time for sequence flattening.

Complexity
----------
- **Time Complexity**: O(1) scalar operations; O(N) sequence operations.
- **Memory Complexity**: O(1) auxiliary space (O(N) for sequence flattening outputs).

Thread Safety
-------------
All utility functions in this module are purely functional and thread-safe.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Ensures protection against NaN injection,
  floating-point overflows, and memory corruption from unvalidated input payloads.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any, TypeVar

from risk_engine.constants import DEFAULT_SCORE_PRECISION, MAX_CONFIDENCE, MIN_CONFIDENCE
from risk_engine.exceptions import InvalidRiskInputError

__all__ = [
    "clamp_score",
    "flatten_sequence",
    "is_valid_probability",
    "normalize_score",
    "round_score",
    "to_immutable_tuple",
    "validate_numeric_score",
]

T = TypeVar("T")


def validate_numeric_score(
    value: float | int,
    field_name: str = "score",
    min_val: float = MIN_CONFIDENCE,
    max_val: float = MAX_CONFIDENCE,
) -> float:
    """
    Validate that a value is a valid, bounded numeric float.

    Args:
        value: Numeric value to validate.
        field_name: Contextual field identifier for diagnostic error payloads.
        min_val: Minimum allowed boundary floor (inclusive).
        max_val: Maximum allowed boundary ceiling (inclusive).

    Returns:
        float: Validated float value.

    Raises:
        InvalidRiskInputError: If value is non-numeric, NaN, Infinite, or out of bounds.
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        raise InvalidRiskInputError(
            message=f"{field_name} must be a valid numeric float, got {value}.",
            details={"field": field_name, "value": value},
        )

    val_float = float(value)
    if not (min_val <= val_float <= max_val):
        raise InvalidRiskInputError(
            message=f"{field_name} must be between {min_val} and {max_val}, got {val_float}.",
            details={"field": field_name, "value": val_float},
        )

    return val_float


def is_valid_probability(value: float | int) -> bool:
    """
    Check whether a value is a valid numeric probability in range [0.0, 1.0].

    Args:
        value: Value to test.

    Returns:
        bool: True if valid probability, False otherwise.
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        return False
    return MIN_CONFIDENCE <= float(value) <= MAX_CONFIDENCE


def clamp_score(
    value: float | int,
    min_val: float = MIN_CONFIDENCE,
    max_val: float = MAX_CONFIDENCE,
) -> float:
    """
    Clamp a numeric score strictly within [min_val, max_val] boundaries.

    Args:
        value: Raw numeric score.
        min_val: Lower bound floor.
        max_val: Upper bound ceiling.

    Returns:
        float: Clamped numeric score.

    Raises:
        InvalidRiskInputError: If value is NaN or Infinite.
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        raise InvalidRiskInputError(
            message=f"Cannot clamp non-numeric value: {value}.",
            details={"field": "value", "value": value},
        )
    return max(min_val, min(max_val, float(value)))


def round_score(
    value: float | int,
    precision: int = DEFAULT_SCORE_PRECISION,
) -> float:
    """
    Round a numeric score to the configured decimal place precision.

    Args:
        value: Numeric score to round.
        precision: Decimal place precision (default 4).

    Returns:
        float: Rounded floating-point score.

    Raises:
        InvalidRiskInputError: If value is NaN or Infinite.
    """
    if not isinstance(value, (int, float)) or math.isnan(value) or math.isinf(value):
        raise InvalidRiskInputError(
            message=f"Cannot round non-numeric value: {value}.",
            details={"field": "value", "value": value},
        )
    return round(float(value), precision)


def normalize_score(
    value: float | int,
    min_val: float = MIN_CONFIDENCE,
    max_val: float = MAX_CONFIDENCE,
    precision: int = DEFAULT_SCORE_PRECISION,
) -> float:
    """
    Clamp a numeric score to bounds and round to decimal precision.

    Args:
        value: Raw numeric score.
        min_val: Lower boundary floor.
        max_val: Upper boundary ceiling.
        precision: Decimal place precision.

    Returns:
        float: Clamped and rounded score.
    """
    clamped = clamp_score(value, min_val=min_val, max_val=max_val)
    return round_score(clamped, precision=precision)


def to_immutable_tuple(items: Iterable[T] | None) -> tuple[T, ...]:
    """
    Safely convert any iterable into an immutable tuple.

    Args:
        items: Optional iterable collection of items.

    Returns:
        tuple[T, ...]: Immutable tuple containing items, or empty tuple if None.
    """
    if items is None:
        return ()
    if isinstance(items, tuple):
        return items
    return tuple(items)


def flatten_sequence(items: Any) -> list[Any]:
    """
    Recursively flatten nested lists/tuples/iterables into a flat list.

    Ignores string and bytes instances to prevent infinite character recursion.

    Args:
        items: Nested payload or collection.

    Returns:
        list[Any]: Flat list of extracted elements.
    """
    if items is None:
        return []

    result: list[Any] = []
    if isinstance(items, (str, bytes)):
        result.append(items)
    elif isinstance(items, Iterable):
        for item in items:
            result.extend(flatten_sequence(item))
    else:
        result.append(items)

    return result
