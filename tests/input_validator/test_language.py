"""
Enterprise-grade unit test suite for LanguageValidator component.

Validates constructor configuration injection, disabled validation mode, supported/unsupported language checks,
warning vs failure modes, custom detector adapters (methods, callables, exception handling), heuristic keyword fallback,
confidence scoring, telemetry metadata formatting, fresh metadata instances, context/request_id propagation,
edge cases, statelessness, and context immutability.
"""

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from input_validator.config import LanguageConfig
from input_validator.exceptions import ValidationExecutionError
from input_validator.models import ValidationResult
from input_validator.validators.language import LanguageValidator

# ===========================================================================
# Mock Detector Adapters
# ===========================================================================


class MockObjectDetectorSingle:
    """Mock detector object exposing a detect() method returning a single language string."""

    def __init__(self, language: str) -> None:
        self.language = language

    def detect(self, prompt: str) -> str:
        return self.language


class MockObjectDetectorTuple:
    """Mock detector object exposing a detect() method returning (language, confidence) tuple."""

    def __init__(self, language: str, confidence: float) -> None:
        self.language = language
        self.confidence = confidence

    def detect(self, prompt: str) -> tuple[str, float]:
        return self.language, self.confidence


class MockCallableDetectorSingle:
    """Mock callable detector returning a single language string."""

    def __init__(self, language: str) -> None:
        self.language = language

    def __call__(self, prompt: str) -> str:
        return self.language


class MockCallableDetectorTuple:
    """Mock callable detector returning a (language, confidence) tuple."""

    def __init__(self, language: str, confidence: float) -> None:
        self.language = language
        self.confidence = confidence

    def __call__(self, prompt: str) -> tuple[str, float]:
        return self.language, self.confidence


class MockExceptionDetector:
    """Mock detector object that raises an exception during detection."""

    def detect(self, prompt: str) -> tuple[str, float]:
        raise RuntimeError("Custom detector pipeline failure")


class DisabledLanguageConfig(LanguageConfig):
    """Subclass of LanguageConfig with enabled attribute set to False for testing disabled mode."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        setattr(self, "enabled", False)


# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for LanguageValidator construction and public properties."""

    def test_constructor_initialization(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en", "hi"],
            default_language="en",
            allow_unknown_languages=False,
        )

        # Act
        validator = LanguageValidator(config=config)

        # Assert
        assert validator.config is config
        assert validator.config.supported_languages == ["en", "hi"]
        assert validator.config.default_language == "en"
        assert validator.config.allow_unknown_languages is False

    def test_validator_name_property(self) -> None:
        # Arrange & Act
        validator = LanguageValidator(config=LanguageConfig())

        # Assert
        assert validator.validator_name == "LanguageValidator"

    def test_priority_property(self) -> None:
        # Arrange & Act
        validator = LanguageValidator(config=LanguageConfig())

        # Assert
        assert validator.priority == 40


# ===========================================================================
# 2. TestValidationDisabled
# ===========================================================================


class TestValidationDisabled:
    """Test suite when language validation is disabled via configuration."""

    def test_validation_succeeds_when_language_validation_disabled(self) -> None:
        # Arrange
        config = DisabledLanguageConfig()
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("Bonjour tout le monde")

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata == {
            "language_enabled": False,
            "validation_passed": True,
        }


# ===========================================================================
# 3. TestSupportedLanguages
# ===========================================================================


class TestSupportedLanguages:
    """Test suite for supported languages validation (English, Hindi, Gujarati)."""

    @pytest.mark.parametrize(
        "prompt, expected_lang, description",
        [
            ("you and I do not have it for the book", "en", "English text"),
            ("यह एक किताब है और वह लिए का की है", "hi", "Hindi text"),
            ("આજે અમો અને છે તે પણ નથી", "gu", "Gujarati text"),
        ],
    )
    def test_supported_languages_validation_succeeds(
        self, prompt: str, expected_lang: str, description: str
    ) -> None:
        # Arrange
        config = LanguageConfig(supported_languages=["en", "hi", "gu"])
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["detected_language"] == expected_lang
        assert result.metadata["language_supported"] is True
        assert result.metadata["validation_passed"] is True


# ===========================================================================
# 4. TestUnsupportedLanguages
# ===========================================================================


class TestUnsupportedLanguages:
    """Test suite for unsupported languages in warning vs hard failure modes."""

    def test_unsupported_language_warning_mode(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"],
            allow_unknown_languages=True,
        )
        validator = LanguageValidator(config=config)
        prompt = "Bonjour tout le monde"  # detected as "unknown"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["detected_language"] == "unknown"
        assert result.metadata["language_supported"] is False
        assert result.metadata["validation_passed"] is True
        assert "warning" in result.metadata
        assert (
            "Detected language 'unknown' is not in supported list"
            in result.metadata["warning"]
        )

    def test_unsupported_language_hard_failure_mode(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"],
            allow_unknown_languages=False,
        )
        validator = LanguageValidator(config=config)
        prompt = "Bonjour tout le monde"  # detected as "unknown"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: detected language 'unknown' is not supported."
        )
        assert result.metadata["detected_language"] == "unknown"
        assert result.metadata["language_supported"] is False
        assert result.metadata["validation_passed"] is False

    def test_request_id_propagation_on_failed_validation(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"],
            allow_unknown_languages=False,
        )
        validator = LanguageValidator(config=config)
        context = {"request_id": "req-fail-id-123"}

        # Act
        result = validator.validate("Bonjour tout le monde", context=context)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is False
        assert result.metadata["request_id"] == "req-fail-id-123"


# ===========================================================================
# 5. TestCustomDetector
# ===========================================================================


class TestCustomDetector:
    """Test suite for custom detector adapters (object methods, callables, exceptions, and preference order)."""

    def test_object_detector_single_return_value(self) -> None:
        # Arrange
        detector = MockObjectDetectorSingle("fr")
        config = LanguageConfig(supported_languages=["fr", "en"], detector=detector)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("any text prompt")

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.metadata["detected_language"] == "fr"
        assert result.metadata["confidence_score"] == 1.0
        assert result.metadata["detection_method"] == "custom_detector"
        assert result.metadata["used_custom_detector"] is True

    def test_object_detector_tuple_return_value(self) -> None:
        # Arrange
        detector = MockObjectDetectorTuple("es", 0.95)
        config = LanguageConfig(supported_languages=["es", "en"], detector=detector)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("any text prompt")

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.metadata["detected_language"] == "es"
        assert result.metadata["confidence_score"] == 0.95
        assert result.metadata["detection_method"] == "custom_detector"
        assert result.metadata["used_custom_detector"] is True

    def test_callable_detector_single_return_value(self) -> None:
        # Arrange
        detector = MockCallableDetectorSingle("de")
        config = LanguageConfig(supported_languages=["de", "en"], detector=detector)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("any text prompt")

        # Assert
        assert result.is_valid is True
        assert result.metadata["detected_language"] == "de"
        assert result.metadata["confidence_score"] == 1.0
        assert result.metadata["used_custom_detector"] is True

    def test_callable_detector_tuple_return_value(self) -> None:
        # Arrange
        detector = MockCallableDetectorTuple("ja", 0.88)
        config = LanguageConfig(supported_languages=["ja", "en"], detector=detector)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("any text prompt")

        # Assert
        assert result.is_valid is True
        assert result.metadata["detected_language"] == "ja"
        assert result.metadata["confidence_score"] == 0.88
        assert result.metadata["used_custom_detector"] is True

    def test_custom_detector_preferred_over_heuristic(self) -> None:
        # Arrange - English text, but custom detector returns "hi"
        detector = MockObjectDetectorTuple("hi", 0.99)
        config = LanguageConfig(supported_languages=["hi", "en"], detector=detector)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("you and I do not have it for the book")

        # Assert
        assert result.metadata["detected_language"] == "hi"
        assert result.metadata["detection_method"] == "custom_detector"
        assert result.metadata["used_custom_detector"] is True

    def test_non_detector_object_falls_back_to_heuristic(self) -> None:
        # Arrange - detector is an integer (neither detect method nor callable)
        config = LanguageConfig(supported_languages=["en"], detector=12345)
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate("you and I do not have it for the book")

        # Assert
        assert result.metadata["detected_language"] == "en"
        assert result.metadata["detection_method"] == "heuristic"
        assert result.metadata["used_custom_detector"] is False

    def test_custom_detector_raising_exception_wraps_in_validation_execution_error(
        self,
    ) -> None:
        # Arrange
        detector = MockExceptionDetector()
        config = LanguageConfig(detector=detector)
        validator = LanguageValidator(config=config)

        # Act & Assert
        with pytest.raises(ValidationExecutionError) as exc_info:
            validator.validate("any text prompt")

        assert exc_info.type is ValidationExecutionError
        assert "Unexpected crash in validator 'LanguageValidator'" in str(
            exc_info.value
        )
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert str(exc_info.value.__cause__) == "Custom detector pipeline failure"


# ===========================================================================
# 6. TestHeuristicDetector
# ===========================================================================


class TestHeuristicDetector:
    """Test suite for local keyword heuristic fallback language detection."""

    @pytest.mark.parametrize(
        "prompt, expected_lang",
        [
            ("you and I do not have it for the book", "en"),
            ("यह एक किताब है और वह लिए का की है", "hi"),
            ("આજે અમો અને છે તે પણ નથી", "gu"),
            ("Lorem ipsum dolor sit amet", "unknown"),
        ],
    )
    def test_heuristic_detection_languages(
        self, prompt: str, expected_lang: str
    ) -> None:
        # Arrange
        config = LanguageConfig(supported_languages=["en", "hi", "gu"])
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.metadata["detected_language"] == expected_lang
        assert result.metadata["detection_method"] == "heuristic"
        assert isinstance(result.metadata["confidence_score"], float)
        assert 0.0 <= result.metadata["confidence_score"] <= 1.0

    def test_mixed_language_prompt_heuristic_scoring(self) -> None:
        # Arrange - 4 English keywords ("you", "and", "I", "do") vs 1 Hindi keyword ("है")
        mixed_prompt = "you and I do है"
        config = LanguageConfig(supported_languages=["en", "hi"])
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate(mixed_prompt)

        # Assert
        assert result.metadata["detected_language"] == "en"
        assert isinstance(result.metadata["confidence_score"], float)
        assert 0.0 <= result.metadata["confidence_score"] <= 1.0


# ===========================================================================
# 7. TestConfiguration
# ===========================================================================


class TestConfiguration:
    """Test suite verifying validator adherence to distinct LanguageConfig objects."""

    def test_multiple_language_config_modes(self) -> None:
        # Arrange
        config_strict = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=False
        )
        config_permissive = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=True
        )

        validator_strict = LanguageValidator(config=config_strict)
        validator_permissive = LanguageValidator(config=config_permissive)

        unknown_prompt = "Bonjour le monde"

        # Act
        result_strict = validator_strict.validate(unknown_prompt)
        result_permissive = validator_permissive.validate(unknown_prompt)

        # Assert
        assert result_strict.is_valid is False
        assert result_permissive.is_valid is True


# ===========================================================================
# 8. TestMetadata
# ===========================================================================


class TestMetadata:
    """Test suite verifying telemetry metadata key-value contract."""

    def test_metadata_structure_on_success(self) -> None:
        # Arrange
        config = LanguageConfig(supported_languages=["en", "hi"], default_language="en")
        validator = LanguageValidator(config=config)
        context = {"request_id": "req-lang-pass"}

        # Act
        result = validator.validate("you and I do not have it", context=context)

        # Assert
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata == {
            "detected_language": "en",
            "confidence_score": 1.0,
            "detection_method": "heuristic",
            "supported_languages": ["en", "hi"],
            "default_language": "en",
            "used_custom_detector": False,
            "language_supported": True,
            "validation_passed": True,
            "request_id": "req-lang-pass",
        }

    def test_metadata_structure_on_warning(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"],
            default_language="en",
            allow_unknown_languages=True,
        )
        validator = LanguageValidator(config=config)
        context = {"request_id": "req-lang-warn"}

        # Act
        result = validator.validate("Bonjour tout le monde", context=context)

        # Assert
        assert result.metadata["language_supported"] is False
        assert result.metadata["validation_passed"] is True
        assert "warning" in result.metadata
        assert result.metadata["request_id"] == "req-lang-warn"

    def test_metadata_dictionary_is_fresh_instance_per_execution(self) -> None:
        # Arrange
        validator = LanguageValidator(config=LanguageConfig())

        # Act
        result_1 = validator.validate("you and I do not have it")
        result_2 = validator.validate("you and I do not have it")

        # Assert
        assert result_1.metadata is not result_2.metadata


# ===========================================================================
# 9. TestValidationResult
# ===========================================================================


class TestValidationResult:
    """Test suite verifying returned ValidationResult attributes, timing, and timezone-aware UTC timestamps."""

    def test_validation_result_contract_success(self) -> None:
        # Arrange
        config = LanguageConfig(supported_languages=["en"])
        validator = LanguageValidator(config=config)
        context = {"request_id": "req-lang-contract-success"}

        # Act
        result = validator.validate("you and I do not have it", context=context)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata["request_id"] == "req-lang-contract-success"

    def test_validation_result_contract_failure(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=False
        )
        validator = LanguageValidator(config=config)
        context = {"request_id": "req-lang-contract-failure"}

        # Act
        result = validator.validate("Bonjour le monde", context=context)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is False
        assert result.error_message is not None
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata["request_id"] == "req-lang-contract-failure"


# ===========================================================================
# 10. TestEdgeCases
# ===========================================================================


class TestEdgeCases:
    """Test suite for edge cases, unicode, emojis, numbers, and symbols."""

    @pytest.mark.parametrize(
        "edge_prompt, description",
        [
            ("", "empty prompt"),
            ("   \t\n  ", "whitespace prompt"),
            ("🌟 Hello 🚀", "unicode with emojis"),
            ("😀😃😄😁", "emojis only"),
            ("1234567890", "numbers only"),
            ("!@#$%^&*()_+-=[]{}", "symbols only"),
            ("a" * 50_000, "very long prompt"),
        ],
    )
    def test_edge_case_prompts_handled(
        self, edge_prompt: str, description: str
    ) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=True
        )
        validator = LanguageValidator(config=config)

        # Act
        result = validator.validate(edge_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True

    @pytest.mark.parametrize("non_string_input", [None, 123, 4.56, [], {}])
    def test_non_string_prompt_handled_by_base_validator(
        self, non_string_input: Any
    ) -> None:
        # Arrange
        validator = LanguageValidator(config=LanguageConfig())

        # Act
        result = validator.validate(non_string_input)

        # Assert
        assert result.is_valid is False
        assert "Input prompt must be a string" in (result.error_message or "")
        assert result.metadata.get("validator_name") == "LanguageValidator"

    def test_validation_with_none_context_normalization(self) -> None:
        # Arrange
        validator = LanguageValidator(config=LanguageConfig())

        # Act
        result = validator.validate("you and I do not have it", context=None)

        # Assert
        assert result.validator_name == "LanguageValidator"
        assert result.is_valid is True
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)


# ===========================================================================
# 11. TestStatelessness
# ===========================================================================


class TestStatelessness:
    """Test suite verifying stateless execution and multi-instance independence."""

    def test_stateless_repeated_execution(self) -> None:
        # Arrange
        config = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=False
        )
        validator = LanguageValidator(config=config)
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            valid_res = validator.validate("you and I do not have it")
            assert valid_res.is_valid is True
            assert isinstance(valid_res.execution_time_ms, float)
            assert valid_res.execution_time_ms >= 0.0

            invalid_res = validator.validate("Bonjour tout le monde")
            assert invalid_res.is_valid is False
            assert isinstance(invalid_res.execution_time_ms, float)
            assert invalid_res.execution_time_ms >= 0.0

    def test_multiple_instances_state_independence(self) -> None:
        # Arrange
        config_a = LanguageConfig(
            supported_languages=["en"], allow_unknown_languages=False
        )
        config_b = LanguageConfig(
            supported_languages=["en", "hi", "gu"], allow_unknown_languages=False
        )

        validator_a = LanguageValidator(config=config_a)
        validator_b = LanguageValidator(config=config_b)

        hindi_prompt = "यह एक किताब है"

        # Act
        res_a = validator_a.validate(hindi_prompt)
        res_b = validator_b.validate(hindi_prompt)

        # Assert
        assert res_a.is_valid is False
        assert res_b.is_valid is True


# ===========================================================================
# 12. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying context dictionary immutability."""

    def test_context_dictionary_is_not_modified(self) -> None:
        # Arrange
        config = LanguageConfig()
        validator = LanguageValidator(config=config)
        original_context = {
            "request_id": "req-lang-immutable",
            "session": {"user": "alice"},
        }
        context_snapshot = copy.deepcopy(original_context)

        # Act
        validator.validate("you and I do not have it", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert original_context["session"]["user"] == "alice"
