"""
Enterprise-grade unit test suite for input_validator.config module.

Validates default initialization, custom values, range boundaries, exception handling,
slots enforcement, mutable default isolation, state independence, and idempotency.
"""

from typing import Any

import pytest

from input_validator.config import (
    DEFAULT_LANGUAGE,
    DEFAULT_MAX_LENGTH,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MIN_LENGTH,
    DEFAULT_SUPPORTED_LANGUAGES,
    DEFAULT_TIMEOUT_MS,
    MAX_LENGTH_LIMIT,
    MAX_TIMEOUT_LIMIT_MS,
    MAX_TOKEN_LIMIT,
    MIN_TIMEOUT_LIMIT_MS,
    InputValidatorConfig,
    LanguageConfig,
    LengthConfig,
    PipelineConfig,
    SchemaConfig,
)
from input_validator.exceptions import ConfigurationError


class DummyDetector:
    """Mock language detector adapter object for testing dependency injection."""

    pass


class DummyProvider:
    """Mock schema provider strategy object for testing dependency injection."""

    pass


# ===========================================================================
# 1. PipelineConfig Tests
# ===========================================================================


class TestPipelineConfig:
    """Test suite for PipelineConfig initialization, validation, and slots."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        config = PipelineConfig()

        # Assert
        assert config.fail_fast is True
        assert config.enable_logging is True
        assert config.timeout_ms == DEFAULT_TIMEOUT_MS
        assert config.continue_on_warning is True

    def test_custom_initialization(self) -> None:
        # Arrange & Act
        config = PipelineConfig(
            fail_fast=False,
            enable_logging=False,
            timeout_ms=5000,
            continue_on_warning=False,
        )

        # Assert
        assert config.fail_fast is False
        assert config.enable_logging is False
        assert config.timeout_ms == 5000
        assert config.continue_on_warning is False

    @pytest.mark.parametrize(
        "valid_timeout",
        [
            MIN_TIMEOUT_LIMIT_MS,
            500,
            DEFAULT_TIMEOUT_MS,
            30000,
            MAX_TIMEOUT_LIMIT_MS,
        ],
    )
    def test_valid_timeout_bounds(self, valid_timeout: int) -> None:
        # Arrange & Act
        config = PipelineConfig(timeout_ms=valid_timeout)

        # Assert
        assert config.timeout_ms == valid_timeout

    @pytest.mark.parametrize(
        "invalid_timeout",
        [
            -100,
            -1,
            0,
            MIN_TIMEOUT_LIMIT_MS - 1,
            MAX_TIMEOUT_LIMIT_MS + 1,
            100000,
        ],
    )
    def test_invalid_timeout_raises_configuration_error(
        self, invalid_timeout: int
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            PipelineConfig(timeout_ms=invalid_timeout)

        assert exc_info.type is ConfigurationError
        assert "timeout_ms" in str(exc_info.value)

    def test_slots_enforcement(self) -> None:
        # Arrange
        config = PipelineConfig()

        # Act & Assert
        with pytest.raises(AttributeError):
            config.undeclared_attribute = "invalid_assignment"  # type: ignore[attr-defined]

    def test_idempotency(self) -> None:
        # Arrange
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            config = PipelineConfig(timeout_ms=2500, fail_fast=False)
            assert config.timeout_ms == 2500
            assert config.fail_fast is False


# ===========================================================================
# 2. LengthConfig Tests
# ===========================================================================


class TestLengthConfig:
    """Test suite for LengthConfig initialization, boundary validation, and slots."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        config = LengthConfig()

        # Assert
        assert config.minimum_length == DEFAULT_MIN_LENGTH
        assert config.maximum_length == DEFAULT_MAX_LENGTH
        assert config.maximum_tokens == DEFAULT_MAX_TOKENS

    def test_custom_initialization(self) -> None:
        # Arrange & Act
        config = LengthConfig(
            minimum_length=10,
            maximum_length=500,
            maximum_tokens=200,
        )

        # Assert
        assert config.minimum_length == 10
        assert config.maximum_length == 500
        assert config.maximum_tokens == 200

    @pytest.mark.parametrize(
        "min_len, max_len, max_tokens",
        [
            (0, 1, 1),
            (0, DEFAULT_MAX_LENGTH, DEFAULT_MAX_TOKENS),
            (100, 200, 50),
            (0, MAX_LENGTH_LIMIT, MAX_TOKEN_LIMIT),
            (999_999, MAX_LENGTH_LIMIT, MAX_TOKEN_LIMIT),
        ],
    )
    def test_valid_boundaries(
        self, min_len: int, max_len: int, max_tokens: int
    ) -> None:
        # Arrange & Act
        config = LengthConfig(
            minimum_length=min_len,
            maximum_length=max_len,
            maximum_tokens=max_tokens,
        )

        # Assert
        assert config.minimum_length == min_len
        assert config.maximum_length == max_len
        assert config.maximum_tokens == max_tokens

    @pytest.mark.parametrize("invalid_min_len", [-1, -100, -5000])
    def test_invalid_minimum_length_raises_configuration_error(
        self, invalid_min_len: int
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            LengthConfig(minimum_length=invalid_min_len)

        assert exc_info.type is ConfigurationError
        assert "minimum_length" in str(exc_info.value)

    @pytest.mark.parametrize(
        "min_len, invalid_max_len",
        [
            (10, 10),
            (10, 5),
            (0, 0),
            (0, MAX_LENGTH_LIMIT + 1),
            (100, MAX_LENGTH_LIMIT + 100),
        ],
    )
    def test_invalid_maximum_length_raises_configuration_error(
        self, min_len: int, invalid_max_len: int
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            LengthConfig(minimum_length=min_len, maximum_length=invalid_max_len)

        assert exc_info.type is ConfigurationError
        assert "maximum_length" in str(exc_info.value)

    @pytest.mark.parametrize(
        "invalid_tokens",
        [-100, -1, 0, MAX_TOKEN_LIMIT + 1, MAX_TOKEN_LIMIT + 500],
    )
    def test_invalid_maximum_tokens_raises_configuration_error(
        self, invalid_tokens: int
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            LengthConfig(maximum_tokens=invalid_tokens)

        assert exc_info.type is ConfigurationError
        assert "maximum_tokens" in str(exc_info.value)

    def test_slots_enforcement(self) -> None:
        # Arrange
        config = LengthConfig()

        # Act & Assert
        with pytest.raises(AttributeError):
            config.undeclared_attribute = 999  # type: ignore[attr-defined]

    def test_idempotency(self) -> None:
        # Arrange
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            config = LengthConfig(minimum_length=5, maximum_length=100)
            assert config.minimum_length == 5
            assert config.maximum_length == 100


# ===========================================================================
# 3. LanguageConfig Tests
# ===========================================================================


class TestLanguageConfig:
    """Test suite for LanguageConfig initialization, state isolation, and validation."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        config = LanguageConfig()

        # Assert
        assert config.supported_languages == list(DEFAULT_SUPPORTED_LANGUAGES)
        assert config.default_language == DEFAULT_LANGUAGE
        assert config.allow_unknown_languages is True
        assert config.detector is None

    def test_custom_initialization(self) -> None:
        # Arrange
        custom_detector = DummyDetector()

        # Act
        config = LanguageConfig(
            supported_languages=["en", "fr", "es"],
            default_language="fr",
            allow_unknown_languages=False,
            detector=custom_detector,
        )

        # Assert
        assert config.supported_languages == ["en", "fr", "es"]
        assert config.default_language == "fr"
        assert config.allow_unknown_languages is False
        assert config.detector is custom_detector

    @pytest.mark.parametrize(
        "supported_langs, default_lang",
        [
            (["en"], "en"),
            (["en", "hi", "gu"], "en"),
            (["en", "hi", "gu", "fr", "es"], "es"),
            (["de", "it", "ja", "ko"], "ja"),
        ],
    )
    def test_valid_supported_languages(
        self, supported_langs: list[str], default_lang: str
    ) -> None:
        # Arrange & Act
        config = LanguageConfig(
            supported_languages=supported_langs,
            default_language=default_lang,
        )

        # Assert
        assert config.supported_languages == supported_langs
        assert config.default_language == default_lang

    def test_empty_supported_languages_raises_configuration_error(self) -> None:
        # Arrange
        empty_list: list[str] = []

        # Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            LanguageConfig(supported_languages=empty_list)

        assert exc_info.type is ConfigurationError
        assert "supported_languages" in str(exc_info.value)

    @pytest.mark.parametrize(
        "supported_langs, invalid_default",
        [
            (["en", "hi"], "fr"),
            (["es"], "en"),
            (["de", "it"], "ja"),
        ],
    )
    def test_default_language_not_in_supported_raises_configuration_error(
        self, supported_langs: list[str], invalid_default: str
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ConfigurationError) as exc_info:
            LanguageConfig(
                supported_languages=supported_langs,
                default_language=invalid_default,
            )

        assert exc_info.type is ConfigurationError
        assert "default_language" in str(exc_info.value)

    def test_mutable_default_isolation(self) -> None:
        # Arrange
        config_1 = LanguageConfig()
        config_2 = LanguageConfig()

        # Act
        config_1.supported_languages.append("fr")

        # Assert
        assert "fr" in config_1.supported_languages
        assert "fr" not in config_2.supported_languages
        assert config_2.supported_languages == list(DEFAULT_SUPPORTED_LANGUAGES)

    def test_independent_instances_state_isolation(self) -> None:
        # Arrange
        config_1 = LanguageConfig(supported_languages=["en", "hi"], default_language="en")
        config_2 = LanguageConfig(supported_languages=["en", "hi"], default_language="en")

        # Act
        config_1.supported_languages.clear()
        config_1.supported_languages.append("es")

        # Assert
        assert config_1.supported_languages == ["es"]
        assert config_2.supported_languages == ["en", "hi"]

    def test_slots_enforcement(self) -> None:
        # Arrange
        config = LanguageConfig()

        # Act & Assert
        with pytest.raises(AttributeError):
            config.undeclared_attribute = "invalid"  # type: ignore[attr-defined]

    def test_idempotency(self) -> None:
        # Arrange
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            config = LanguageConfig(
                supported_languages=["en", "de"], default_language="de"
            )
            assert config.default_language == "de"
            assert config.supported_languages == ["en", "de"]


# ===========================================================================
# 4. SchemaConfig Tests
# ===========================================================================


class TestSchemaConfig:
    """Test suite for SchemaConfig initialization, mutable defaults, and slots."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        config = SchemaConfig()

        # Assert
        assert config.enable_schema_validation is False
        assert config.required_fields == {}
        assert config.allow_extra_fields is True
        assert config.parse_json is False
        assert config.provider is None

    def test_custom_initialization(self) -> None:
        # Arrange
        required_schema = {"query": str, "user_id": int}
        custom_provider = DummyProvider()

        # Act
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields=required_schema,
            allow_extra_fields=False,
            parse_json=True,
            provider=custom_provider,
        )

        # Assert
        assert config.enable_schema_validation is True
        assert config.required_fields == required_schema
        assert config.allow_extra_fields is False
        assert config.parse_json is True
        assert config.provider is custom_provider

    def test_mutable_default_isolation(self) -> None:
        # Arrange
        config_1 = SchemaConfig()
        config_2 = SchemaConfig()

        # Act
        config_1.required_fields["new_field"] = str

        # Assert
        assert "new_field" in config_1.required_fields
        assert "new_field" not in config_2.required_fields
        assert config_2.required_fields == {}

    def test_independent_instances_state_isolation(self) -> None:
        # Arrange
        initial_fields_1 = {"field_a": str}
        initial_fields_2 = {"field_b": int}

        config_1 = SchemaConfig(required_fields=initial_fields_1)
        config_2 = SchemaConfig(required_fields=initial_fields_2)

        # Act
        config_1.required_fields["extra"] = bool

        # Assert
        assert "extra" in config_1.required_fields
        assert "extra" not in config_2.required_fields

    def test_slots_enforcement(self) -> None:
        # Arrange
        config = SchemaConfig()

        # Act & Assert
        with pytest.raises(AttributeError):
            config.undeclared_attribute = True  # type: ignore[attr-defined]

    def test_idempotency(self) -> None:
        # Arrange
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            config = SchemaConfig(parse_json=True, allow_extra_fields=False)
            assert config.parse_json is True
            assert config.allow_extra_fields is False


# ===========================================================================
# 5. InputValidatorConfig (Root Config) Tests
# ===========================================================================


class TestInputValidatorConfig:
    """Test suite for root InputValidatorConfig component orchestration and injection."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        config = InputValidatorConfig()

        # Assert
        assert isinstance(config.pipeline, PipelineConfig)
        assert isinstance(config.length, LengthConfig)
        assert isinstance(config.language, LanguageConfig)
        assert isinstance(config.schema, SchemaConfig)
        assert config.extensions == {}

    def test_custom_components_injection(self) -> None:
        # Arrange
        pipeline = PipelineConfig(timeout_ms=3000, fail_fast=False)
        length = LengthConfig(minimum_length=10, maximum_length=1000)
        language = LanguageConfig(
            supported_languages=["en", "es"], default_language="es"
        )
        schema = SchemaConfig(enable_schema_validation=True)
        extensions = {"rate_limiter": {"max": 50}}

        # Act
        config = InputValidatorConfig(
            pipeline=pipeline,
            length=length,
            language=language,
            schema=schema,
            extensions=extensions,
        )

        # Assert
        assert config.pipeline is pipeline
        assert config.length is length
        assert config.language is language
        assert config.schema is schema
        assert config.extensions is extensions

    def test_mutable_default_isolation(self) -> None:
        # Arrange
        config_1 = InputValidatorConfig()
        config_2 = InputValidatorConfig()

        # Act
        config_1.extensions["custom_plugin"] = True

        # Assert
        assert "custom_plugin" in config_1.extensions
        assert "custom_plugin" not in config_2.extensions
        assert config_2.extensions == {}

    def test_independent_instances_state_isolation(self) -> None:
        # Arrange
        config_1 = InputValidatorConfig()
        config_2 = InputValidatorConfig()

        # Act
        config_1.pipeline.timeout_ms = 5000
        config_1.language.supported_languages.append("de")
        config_1.schema.required_fields["id"] = int

        # Assert
        assert config_2.pipeline.timeout_ms == DEFAULT_TIMEOUT_MS
        assert "de" not in config_2.language.supported_languages
        assert "id" not in config_2.schema.required_fields

    def test_slots_enforcement(self) -> None:
        # Arrange
        config = InputValidatorConfig()

        # Act & Assert
        with pytest.raises(AttributeError):
            config.undeclared_attribute = "root"  # type: ignore[attr-defined]

    def test_idempotency(self) -> None:
        # Arrange
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            config = InputValidatorConfig()
            assert config.pipeline.timeout_ms == DEFAULT_TIMEOUT_MS
            assert config.length.minimum_length == DEFAULT_MIN_LENGTH
            assert config.language.default_language == DEFAULT_LANGUAGE
            assert config.schema.enable_schema_validation is False
            assert config.extensions == {}
