"""
Configuration classes for the Input Validator framework.

Provides memory-efficient, mutable configuration structures with range validations
for pipeline and validator constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from input_validator.exceptions import ConfigurationError

# ===========================================================================
# Module Constants
# ===========================================================================

DEFAULT_TIMEOUT_MS: int = 1000
MIN_TIMEOUT_LIMIT_MS: int = 1
MAX_TIMEOUT_LIMIT_MS: int = 60000

DEFAULT_MIN_LENGTH: int = 0
DEFAULT_MAX_LENGTH: int = 50000
DEFAULT_MAX_TOKENS: int = 8000

MAX_LENGTH_LIMIT: int = 10_000_000
MAX_TOKEN_LIMIT: int = 1_000_000

DEFAULT_SUPPORTED_LANGUAGES: tuple[str, ...] = (
    "en",
    "hi",
    "gu",
)
DEFAULT_LANGUAGE: str = "en"


# ===========================================================================
# Internal Validation Helper Functions
# ===========================================================================


def _validate_range(
    value: int | float, 
    name: str, 
    min_val: int | float, 
    max_val: int | float
) -> None:
    """Validates that a numeric configuration value falls within a given range."""
    if not (min_val <= value <= max_val):
        raise ConfigurationError(
            f"Configuration validation failed: '{name}' must be between {min_val} and {max_val}, got {value}"
        )


def _validate_non_negative(value: int | float, name: str) -> None:
    """Validates that a numeric configuration value is non-negative."""
    if value < 0:
        raise ConfigurationError(
            f"Configuration validation failed: '{name}' must be non-negative, got {value}"
        )


def _validate_min_max(
    min_val: int | float, 
    max_val: int | float, 
    min_name: str, 
    max_name: str
) -> None:
    """Validates that a minimum configuration limit is strictly less than its maximum counterpart."""
    if min_val >= max_val:
        raise ConfigurationError(
            f"Configuration validation failed: '{max_name}' ({max_val}) "
            f"must be strictly greater than '{min_name}' ({min_val})"
        )


# ===========================================================================
# Configuration Classes
# ===========================================================================


@dataclass(slots=True)
class PipelineConfig:
    """
    Configuration settings governing the validation pipeline execution.

    Attributes:
        fail_fast (bool): If True, halts execution on the first failed validator check.
        enable_logging (bool): If True, enables execution telemetry logs.
        timeout_ms (int): Execution timeout limit in milliseconds. Must be between 1 and 60000.
        continue_on_warning (bool): If True, warnings do not halt execution.
    """

    fail_fast: bool = True
    enable_logging: bool = True
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    continue_on_warning: bool = True

    def __post_init__(self) -> None:
        """Validates configuration parameters."""
        _validate_range(
            self.timeout_ms, "timeout_ms", MIN_TIMEOUT_LIMIT_MS, MAX_TIMEOUT_LIMIT_MS
        )


@dataclass(slots=True)
class LengthConfig:
    """
    Configuration settings governing input prompt length boundaries.

    Attributes:
        minimum_length (int): Minimum length of prompt in characters. Must be >= 0.
        maximum_length (int): Maximum length of prompt in characters. Must be > minimum_length.
        maximum_tokens (int): Maximum token boundary limits. Must be > 0.
    """

    minimum_length: int = DEFAULT_MIN_LENGTH
    maximum_length: int = DEFAULT_MAX_LENGTH
    maximum_tokens: int = DEFAULT_MAX_TOKENS

    def __post_init__(self) -> None:
        """Validates configuration parameters."""
        _validate_non_negative(self.minimum_length, "minimum_length")
        _validate_range(
            self.maximum_length,
            "maximum_length",
            self.minimum_length + 1,
            MAX_LENGTH_LIMIT,
        )
        _validate_range(self.maximum_tokens, "maximum_tokens", 1, MAX_TOKEN_LIMIT)
        _validate_min_max(
            self.minimum_length, self.maximum_length, "minimum_length", "maximum_length"
        )


@dataclass(slots=True)
class LanguageConfig:
    """
    Configuration settings governing supported languages and defaults.

    Attributes:
        supported_languages (list[str]): List of ISO codes. Must not be empty.
        default_language (str): Mapped fallback language. Must exist inside supported_languages.
        allow_unknown_languages (bool): If True, unknown languages generate warnings instead of failures.
        detector (Any): Custom LanguageDetector adapter instance.
            # TODO: Replace Any with LanguageDetectorProtocol in Sprint 6.1
    """

    supported_languages: list[str] = field(
        default_factory=lambda: list(DEFAULT_SUPPORTED_LANGUAGES)
    )
    default_language: str = DEFAULT_LANGUAGE
    allow_unknown_languages: bool = True
    detector: Any = None

    def __post_init__(self) -> None:
        """Validates configuration parameters."""
        if not self.supported_languages:
            raise ConfigurationError(
                "Configuration validation failed: 'supported_languages' list must not be empty"
            )
        if self.default_language not in self.supported_languages:
            raise ConfigurationError(
                f"Configuration validation failed: 'default_language' '{self.default_language}' "
                f"must exist inside 'supported_languages': {self.supported_languages}"
            )


@dataclass(slots=True)
class SchemaConfig:
    """
    Configuration settings governing request structure validation.

    Attributes:
        enable_schema_validation (bool): If True, triggers schema checks.
        required_fields (dict[str, Any]): Dictionary mapping fields to expected Python types.
        allow_extra_fields (bool): If True, additional fields in dict payload are allowed.
        parse_json (bool): If True, string inputs are deserialized from JSON before validation.
        provider (Any): Custom SchemaProvider strategy instance.
            # TODO: Replace Any with SchemaProviderProtocol in Sprint 6.1
    """

    enable_schema_validation: bool = False
    required_fields: dict[str, Any] = field(default_factory=dict)
    allow_extra_fields: bool = True
    parse_json: bool = False
    provider: Any = None


@dataclass(slots=True)
class InputValidatorConfig:
    """
    Root configuration orchestrating settings across the Input Validator framework.

    Attributes:
        pipeline (PipelineConfig): Validation pipeline run settings.
        length (LengthConfig): Character length constraints.
        language (LanguageConfig): Language detection constraints.
        schema (SchemaConfig): Dictionary schema parameters.
        extensions (dict[str, Any]): Framework extension settings for pluggable validators.
    """

    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    length: LengthConfig = field(default_factory=LengthConfig)
    language: LanguageConfig = field(default_factory=LanguageConfig)
    schema: SchemaConfig = field(default_factory=SchemaConfig)
    extensions: dict[str, Any] = field(default_factory=dict)


# ===========================================================================
# Future Configuration Placeholders
# ===========================================================================

# TODO: Implement EncodingConfig for charset/byte verification validation settings.
# TODO: Implement FormatConfig for formatting patterns (regex, UUID, URL) validation settings.
# TODO: Implement FileConfig for file payload constraints (extension, file size, mime-type) settings.
# TODO: Implement ContextConfig for conversational history boundary settings.
# TODO: Implement CompletenessConfig for semantic input completion validation settings.
