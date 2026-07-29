"""
Unit tests for risk_engine.utils — Sprint 7 Verification Phase.

Tests all pure utility functions in risk_engine.utils:
    - validate_numeric_score()
    - is_valid_probability()
    - clamp_score()
    - round_score()
    - normalize_score()
    - to_immutable_tuple()
    - flatten_sequence()
"""

from __future__ import annotations

import math
import pytest

from risk_engine.exceptions import InvalidRiskInputError
from risk_engine.utils import (
    clamp_score,
    flatten_sequence,
    is_valid_probability,
    normalize_score,
    round_score,
    to_immutable_tuple,
    validate_numeric_score,
)


# =============================================================================
# 1. validate_numeric_score() Tests
# =============================================================================


def test_validate_numeric_score_valid_float():
    """Verify valid float score within [0.0, 1.0] passes validation."""
    # Arrange
    score = 0.75

    # Act
    result = validate_numeric_score(score)

    # Assert
    assert result == 0.75


def test_validate_numeric_score_valid_int():
    """Verify valid integer score converts to float and passes validation."""
    # Arrange & Act
    result_zero = validate_numeric_score(0)
    result_one = validate_numeric_score(1)

    # Assert
    assert result_zero == 0.0
    assert result_one == 1.0


def test_validate_numeric_score_boundaries():
    """Verify exact boundary values 0.0 and 1.0 pass validation."""
    # Arrange & Act & Assert
    assert validate_numeric_score(0.0) == 0.0
    assert validate_numeric_score(1.0) == 1.0


def test_validate_numeric_score_custom_bounds():
    """Verify validation respects custom min_val and max_val parameters."""
    # Arrange & Act
    result = validate_numeric_score(5.0, field_name="custom_score", min_val=0.0, max_val=10.0)

    # Assert
    assert result == 5.0


def test_validate_numeric_score_negative_raises():
    """Verify negative score raises InvalidRiskInputError."""
    # Arrange
    score = -0.01

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        validate_numeric_score(score)
    assert "must be between" in exc_info.value.message


def test_validate_numeric_score_exceeds_max_raises():
    """Verify score exceeding max_val raises InvalidRiskInputError."""
    # Arrange
    score = 1.0001

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        validate_numeric_score(score)
    assert "must be between" in exc_info.value.message


def test_validate_numeric_score_nan_raises():
    """Verify NaN input raises InvalidRiskInputError."""
    # Arrange
    score = float("nan")

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        validate_numeric_score(score)
    assert "valid numeric float" in exc_info.value.message


def test_validate_numeric_score_inf_raises():
    """Verify positive and negative Infinity raise InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        validate_numeric_score(float("inf"))

    with pytest.raises(InvalidRiskInputError):
        validate_numeric_score(float("-inf"))


def test_validate_numeric_score_invalid_type_raises():
    """Verify non-numeric types raise InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        validate_numeric_score("0.5")  # type: ignore[arg-type]

    with pytest.raises(InvalidRiskInputError):
        validate_numeric_score(None)  # type: ignore[arg-type]

    with pytest.raises(InvalidRiskInputError):
        validate_numeric_score([0.5])  # type: ignore[arg-type]


# =============================================================================
# 2. is_valid_probability() Tests
# =============================================================================


def test_is_valid_probability_valid_values():
    """Verify valid probability inputs return True."""
    # Act & Assert
    assert is_valid_probability(0.0) is True
    assert is_valid_probability(0.5) is True
    assert is_valid_probability(1.0) is True
    assert is_valid_probability(0) is True
    assert is_valid_probability(1) is True


def test_is_valid_probability_out_of_bounds():
    """Verify out-of-bounds inputs return False."""
    # Act & Assert
    assert is_valid_probability(-0.001) is False
    assert is_valid_probability(1.001) is False
    assert is_valid_probability(10.0) is False
    assert is_valid_probability(-5) is False


def test_is_valid_probability_nan_and_inf():
    """Verify NaN and Infinity inputs return False."""
    # Act & Assert
    assert is_valid_probability(float("nan")) is False
    assert is_valid_probability(float("inf")) is False
    assert is_valid_probability(float("-inf")) is False


def test_is_valid_probability_invalid_types():
    """Verify non-numeric inputs return False cleanly without raising."""
    # Act & Assert
    assert is_valid_probability("0.5") is False  # type: ignore[arg-type]
    assert is_valid_probability(None) is False  # type: ignore[arg-type]
    assert is_valid_probability([]) is False  # type: ignore[arg-type]


# =============================================================================
# 3. clamp_score() Tests
# =============================================================================


def test_clamp_score_within_range():
    """Verify score within boundaries remains unchanged."""
    # Act & Assert
    assert clamp_score(0.42) == 0.42


def test_clamp_score_below_min():
    """Verify score below min_val is clamped to min_val."""
    # Act & Assert
    assert clamp_score(-0.5) == 0.0


def test_clamp_score_above_max():
    """Verify score above max_val is clamped to max_val."""
    # Act & Assert
    assert clamp_score(1.5) == 1.0


def test_clamp_score_boundaries():
    """Verify exact boundary values remain intact when clamped."""
    # Act & Assert
    assert clamp_score(0.0) == 0.0
    assert clamp_score(1.0) == 1.0


def test_clamp_score_custom_bounds():
    """Verify clamping respects custom min_val and max_val boundaries."""
    # Act & Assert
    assert clamp_score(-5.0, min_val=-1.0, max_val=1.0) == -1.0
    assert clamp_score(15.0, min_val=0.0, max_val=10.0) == 10.0
    assert clamp_score(5.0, min_val=0.0, max_val=10.0) == 5.0


def test_clamp_score_nan_raises():
    """Verify NaN score raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        clamp_score(float("nan"))


def test_clamp_score_inf_raises():
    """Verify Infinity raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        clamp_score(float("inf"))


def test_clamp_score_invalid_type_raises():
    """Verify non-numeric input raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        clamp_score("invalid")  # type: ignore[arg-type]


# =============================================================================
# 4. round_score() Tests
# =============================================================================


def test_round_score_default_precision():
    """Verify default rounding precision is 4 decimal places."""
    # Arrange
    val = 0.123456789

    # Act
    result = round_score(val)

    # Assert
    assert result == 0.1235


def test_round_score_custom_precision():
    """Verify custom decimal precision rounding."""
    # Arrange & Act & Assert
    assert round_score(0.123456, precision=2) == 0.12
    assert round_score(0.123456, precision=6) == 0.123456
    assert round_score(0.678, precision=0) == 1.0


def test_round_score_nan_raises():
    """Verify NaN score raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        round_score(float("nan"))


def test_round_score_inf_raises():
    """Verify Infinity score raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        round_score(float("inf"))


def test_round_score_invalid_type_raises():
    """Verify non-numeric input raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        round_score("0.5")  # type: ignore[arg-type]


# =============================================================================
# 5. normalize_score() Tests
# =============================================================================


def test_normalize_score_combines_clamping_and_rounding():
    """Verify normalize_score clamps and rounds in a single operation."""
    # Act & Assert
    assert normalize_score(1.234567) == 1.0
    assert normalize_score(-0.5) == 0.0
    assert normalize_score(0.56789) == 0.5679


def test_normalize_score_custom_bounds_and_precision():
    """Verify normalize_score respects custom bounds and precision."""
    # Act & Assert
    assert normalize_score(15.6789, min_val=0.0, max_val=10.0, precision=2) == 10.0
    assert normalize_score(5.6789, min_val=0.0, max_val=10.0, precision=2) == 5.68


def test_normalize_score_nan_raises():
    """Verify NaN input raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        normalize_score(float("nan"))


def test_normalize_score_inf_raises():
    """Verify Infinity input raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError):
        normalize_score(float("inf"))


# =============================================================================
# 6. to_immutable_tuple() Tests
# =============================================================================


def test_to_immutable_tuple_from_list():
    """Verify list converts to tuple."""
    # Act & Assert
    assert to_immutable_tuple([1, 2, 3]) == (1, 2, 3)


def test_to_immutable_tuple_from_tuple():
    """Verify existing tuple is returned as-is."""
    # Arrange
    tup = (1, 2, 3)

    # Act & Assert
    assert to_immutable_tuple(tup) is tup


def test_to_immutable_tuple_from_generator():
    """Verify generator expression converts to tuple."""
    # Arrange
    gen = (x * 2 for x in range(3))

    # Act & Assert
    assert to_immutable_tuple(gen) == (0, 2, 4)


def test_to_immutable_tuple_from_none():
    """Verify None input converts to empty tuple."""
    # Act & Assert
    assert to_immutable_tuple(None) == ()


def test_to_immutable_tuple_from_empty():
    """Verify empty iterable converts to empty tuple."""
    # Act & Assert
    assert to_immutable_tuple([]) == ()


# =============================================================================
# 7. flatten_sequence() Tests
# =============================================================================


def test_flatten_sequence_flat_list():
    """Verify flat list remains unchanged."""
    # Act & Assert
    assert flatten_sequence([1, 2, 3]) == [1, 2, 3]


def test_flatten_sequence_nested_list():
    """Verify deeply nested lists and tuples are flattened."""
    # Arrange
    nested = [1, [2, (3, [4, 5])], 6]

    # Act & Assert
    assert flatten_sequence(nested) == [1, 2, 3, 4, 5, 6]


def test_flatten_sequence_with_strings():
    """Verify string items are preserved as scalar elements without character iteration."""
    # Arrange
    nested = ["hello", ["world", "test"]]

    # Act & Assert
    assert flatten_sequence(nested) == ["hello", "world", "test"]


def test_flatten_sequence_with_bytes():
    """Verify bytes items are preserved as scalar elements without byte iteration."""
    # Arrange
    nested = [b"data", [b"stream"]]

    # Act & Assert
    assert flatten_sequence(nested) == [b"data", b"stream"]


def test_flatten_sequence_none_returns_empty():
    """Verify None input returns an empty list."""
    # Act & Assert
    assert flatten_sequence(None) == []


def test_flatten_sequence_single_scalar():
    """Verify single scalar element is wrapped in a list."""
    # Act & Assert
    assert flatten_sequence(42) == [42]


def test_flatten_sequence_empty():
    """Verify empty list returns empty list."""
    # Act & Assert
    assert flatten_sequence([]) == []
