"""
Unit tests for the TextNormalizer class.

Verifies input validation, Unicode normalization, invisible/control characters removal,
whitespace collapsing, result/metadata structures, serialization, and error scenarios.
"""

from unittest.mock import patch
import pytest

from security.exceptions import ConfigurationError, NormalizationError, ValidationError
from security.models import NormalizationMetadata, NormalizationResult
from security.normalizer import NormalizationConfig, TextNormalizer


@pytest.fixture
def default_normalizer() -> TextNormalizer:
    """Provides a TextNormalizer configured with default settings."""
    return TextNormalizer()


def test_normalization_config_defaults() -> None:
    """Verifies default configuration options are set correctly."""
    # Arrange & Act
    config = NormalizationConfig()

    # Assert
    assert config.unicode_form == "NFKC"
    assert config.remove_invisible is True
    assert config.normalize_whitespace is True
    assert config.preserve_newlines is False
    assert config.remove_control_chars is True


@pytest.mark.parametrize("form", ["NFC", "NFD", "NFKC", "NFKD"])
def test_normalization_config_valid_forms(form: str) -> None:
    """Verifies that all standard Unicode forms are accepted."""
    # Arrange & Act
    config = NormalizationConfig(unicode_form=form)

    # Assert
    assert config.unicode_form == form


def test_normalization_config_invalid_form_raises() -> None:
    """Verifies that an unsupported Unicode form raises a ConfigurationError."""
    # Arrange, Act & Assert
    with pytest.raises(ConfigurationError) as exc_info:
        NormalizationConfig(unicode_form="INVALID_FORM")
    assert "Unsupported unicode_form" in str(exc_info.value)


@pytest.mark.parametrize(
    "invalid_input",
    [
        None,
        123,
        ["not a string"],
        {"prompt": "text"},
    ],
)
def test_input_validation_invalid_types_raise(default_normalizer: TextNormalizer, invalid_input: any) -> None:
    """Verifies that invalid input types raise a ValidationError."""
    # Arrange, Act & Assert
    with pytest.raises(ValidationError) as exc_info:
        default_normalizer.normalize_text(invalid_input)
    assert "Input text" in str(exc_info.value)


@pytest.mark.parametrize(
    "text, expected_normalized, expected_removed",
    [
        ("", "", 0),
        ("   ", "", 2),
        ("Normal text", "Normal text", 1),
    ],
)
def test_input_validation_boundaries(
    default_normalizer: TextNormalizer, text: str, expected_normalized: str, expected_removed: int
) -> None:
    """Verifies boundary text cases produce correct output strings and removal counts."""
    # Arrange & Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == expected_normalized
    assert result.metadata.characters_removed == expected_removed


def test_unicode_normalization_nfkc_collapsing(default_normalizer: TextNormalizer) -> None:
    """Verifies NFKC collapses compatibility variants (superscripts, ligatures) properly."""
    # Arrange
    text = "2⁵ and ﬁ"  # superscript 5 and ligature fi

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "25 and fi"
    assert result.metadata.unicode_changes > 0


def test_unicode_normalization_homoglyph(default_normalizer: TextNormalizer) -> None:
    """Verifies unicode fullwidth homoglyph characters are unified."""
    # Arrange
    text = "Ｈｅｌｌｏ"  # fullwidth characters

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "Hello"
    assert result.metadata.unicode_changes == 5


@pytest.mark.parametrize(
    "invisible_char, name",
    [
        ("\u200B", "Zero Width Space"),
        ("\u200C", "Zero Width Non-Joiner"),
        ("\u200D", "Zero Width Joiner"),
        ("\u2060", "Word Joiner"),
        ("\uFEFF", "BOM / Zero Width No-Break Space"),
    ],
)
def test_invisible_character_removal(default_normalizer: TextNormalizer, invisible_char: str, name: str) -> None:
    """Verifies different types of invisible characters are successfully stripped."""
    # Arrange
    text = f"P{invisible_char}r{invisible_char}o{invisible_char}m{invisible_char}p{invisible_char}t"

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "Prompt", f"Failed to strip {name}"
    assert result.metadata.characters_removed == 5


@pytest.mark.parametrize(
    "control_char, name",
    [
        ("\x00", "NULL"),
        ("\x07", "BEL"),
        ("\x0B", "Vertical Tab"),
        ("\x7F", "DEL"),
    ],
)
def test_control_character_removal(default_normalizer: TextNormalizer, control_char: str, name: str) -> None:
    """Verifies control characters are cleanly removed and logged in metadata."""
    # Arrange
    text = f"Clean{control_char}Text"

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "CleanText", f"Failed to remove {name}"
    assert result.metadata.control_characters_removed == 1
    assert result.metadata.characters_removed == 1


@pytest.mark.parametrize(
    "input_text, expected_output, expected_removals",
    [
        ("Multiple   spaces", "Multiple spaces", 1),
        ("With\ttabs", "With tabs", 1),  # Tab is collapsed to single space (length unchanged)
        ("Mixed \t  whitespace", "Mixed whitespace", 1),
    ],
)
def test_whitespace_normalization_standard(
    default_normalizer: TextNormalizer, input_text: str, expected_output: str, expected_removals: int
) -> None:
    """Verifies standard whitespace collapses to single spaces and trims margins."""
    # Arrange & Act
    result = default_normalizer.normalize_text(input_text)

    # Assert
    assert result.normalized_text == expected_output
    assert result.metadata.characters_removed == expected_removals


def test_whitespace_normalization_preserve_newlines() -> None:
    """Verifies horizontal collapses happen but vertical newlines are kept when configured."""
    # Arrange
    config = NormalizationConfig(preserve_newlines=True)
    normalizer = TextNormalizer(config)
    text = "Line 1   \t\n  Line 2  \n\n  Line 3  "

    # Act
    result = normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "Line 1\nLine 2\n\nLine 3"
    assert result.metadata.characters_removed > 0


def test_whitespace_normalization_strip_newlines(default_normalizer: TextNormalizer) -> None:
    """Verifies newlines collapse to single horizontal spaces under default settings."""
    # Arrange
    text = "Line 1\nLine 2\n\nLine 3"

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.normalized_text == "Line 1 Line 2 Line 3"


def test_returned_objects_and_metadata_fields(default_normalizer: TextNormalizer) -> None:
    """Verifies result and metadata classes contain all necessary fields and correct typings."""
    # Arrange
    text = "Test prompt."

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert isinstance(result, NormalizationResult)
    assert isinstance(result.metadata, NormalizationMetadata)
    assert isinstance(result.normalized_text, str)
    assert isinstance(result.metadata.characters_removed, int)
    assert isinstance(result.metadata.unicode_changes, int)
    assert isinstance(result.metadata.control_characters_removed, int)
    assert isinstance(result.metadata.processing_time_ms, float)


def test_performance_metadata_timing(default_normalizer: TextNormalizer) -> None:
    """Verifies processing latency is always recorded and is non-negative."""
    # Arrange
    text = "Performant execution validation."

    # Act
    result = default_normalizer.normalize_text(text)

    # Assert
    assert result.metadata.processing_time_ms >= 0.0


def test_normalization_error_handling() -> None:
    """Verifies unexpected internal normalization crashes raise a NormalizationError."""
    # Arrange
    normalizer = TextNormalizer()
    text = "Input String"

    # Act & Assert
    with patch("unicodedata.normalize", side_effect=ValueError("Mocked unicode crash")):
        with pytest.raises(NormalizationError) as exc_info:
            normalizer.normalize_text(text)
        assert "Text normalization pipeline failed" in str(exc_info.value)


def test_normalization_serialization(default_normalizer: TextNormalizer) -> None:
    """Verifies dictionary serialization outputs accurate keys and values."""
    # Arrange
    text = "Hello\x00 World"

    # Act
    result = default_normalizer.normalize_text(text)
    serialized_result = result.to_dict()
    serialized_metadata = result.metadata.to_dict()

    # Assert
    # Validate result dictionary structure
    assert serialized_result["normalized_text"] == "Hello World"
    assert "metadata" in serialized_result
    
    # Validate metadata dictionary structure
    assert serialized_metadata["characters_removed"] == 2
    assert serialized_metadata["unicode_changes"] == 0
    assert serialized_metadata["control_characters_removed"] == 1
    assert isinstance(serialized_metadata["processing_time_ms"], float)
