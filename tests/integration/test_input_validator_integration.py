"""
Integration test suite for the public InputValidator facade component.

This test suite exercises the complete end-to-end integration flow using **real**
production implementations shipped with the framework:
    - InputValidator (public facade)
    - InputValidatorConfig and sub-configs (LengthConfig, PipelineConfig, LanguageConfig, SchemaConfig)
    - ValidationPipeline (internal execution pipeline)
    - Concrete production validators (EmptyValidator, LengthValidator, EncodingValidator,
      FormatValidator, SchemaValidator, FileValidator, LanguageValidator,
      ContextRulesValidator, CompletenessValidator)

The suite strictly tests the public API of InputValidator without accessing private
internal attributes or helper methods, following the Arrange-Act-Assert (AAA) pattern.
"""

from __future__ import annotations

import copy

import pytest

# ---------------------------------------------------------------------------
# Production Component Imports
# ---------------------------------------------------------------------------
from input_validator.config import (
    InputValidatorConfig,
    LanguageConfig,
    LengthConfig,
    PipelineConfig,
    SchemaConfig,
)
from input_validator.exceptions import ValidationError
from input_validator.input_validator import InputValidator
from input_validator.models import InputValidationResponse, ValidationResult
from input_validator.pipeline import ValidationPipeline
from input_validator.validators.base_validator import BaseValidator
from input_validator.validators.completeness import CompletenessValidator
from input_validator.validators.context_rules import ContextRulesValidator
from input_validator.validators.empty import EmptyValidator
from input_validator.validators.encoding import EncodingValidator
from input_validator.validators.file_validator import FileValidator
from input_validator.validators.format import FormatValidator
from input_validator.validators.language import LanguageValidator
from input_validator.validators.length import LengthValidator
from input_validator.validators.schema import SchemaValidator

# ---------------------------------------------------------------------------
# Test Constants & Helper Functions
# ---------------------------------------------------------------------------
VALID_PROMPT = (
    "Hello world! This is a valid enterprise prompt for testing the input "
    "validator facade integration."
)

VALID_CONTEXT = {
    "user": "secops_admin",
    "request_id": "req-998877",
}


def create_all_validators(
    cfg: InputValidatorConfig | None = None,
) -> list[BaseValidator]:
    """
    Constructs a list containing one instance of every real concrete validator
    shipped with the production framework, bound to the provided configuration.
    """
    config = cfg or InputValidatorConfig()
    return [
        EmptyValidator(config=config),
        LengthValidator(config=config.length),
        EncodingValidator(config=config),
        FormatValidator(config=config),
        SchemaValidator(config=config.schema),
        FileValidator(config=config),
        LanguageValidator(config=config.language),
        ContextRulesValidator(config=config),
        CompletenessValidator(config=config),
    ]


# ===========================================================================
# 1. TestConstruction
# ===========================================================================
class TestConstruction:
    """Verifies default and custom construction patterns for InputValidator."""

    def test_default_construction(self) -> None:
        # Arrange & Act
        validator = InputValidator()

        # Assert
        assert isinstance(validator, InputValidator)
        assert isinstance(validator.registered_validators(), list)
        assert isinstance(validator.version, str)
        assert validator.version == "1.0.0"

    def test_construction_with_injected_config(self) -> None:
        # Arrange
        custom_cfg = InputValidatorConfig(
            length=LengthConfig(minimum_length=5, maximum_length=100)
        )

        # Act
        validator = InputValidator(config=custom_cfg)

        # Assert
        assert isinstance(validator, InputValidator)

    def test_construction_with_injected_pipeline(self) -> None:
        # Arrange
        validators = create_all_validators()
        pipe_cfg = PipelineConfig(fail_fast=False)
        custom_pipeline = ValidationPipeline(validators=validators, config=pipe_cfg)

        # Act
        validator = InputValidator(pipeline=custom_pipeline)

        # Assert
        assert validator.pipeline is custom_pipeline
        assert len(validator.registered_validators()) == len(validators)

    def test_construction_with_injected_validator_list(self) -> None:
        # Arrange
        validators = create_all_validators()

        # Act
        validator = InputValidator(validators=validators)

        # Assert
        registered = validator.registered_validators()
        assert len(registered) == len(validators)
        priorities = [v.priority for v in registered]
        assert priorities == sorted(priorities)

    def test_multiple_independent_instances_construction(self) -> None:
        # Arrange & Act
        all_validators = create_all_validators()
        v1 = InputValidator(validators=all_validators)
        v2 = InputValidator(validators=[EmptyValidator(InputValidatorConfig())])

        # Assert
        assert len(v1.registered_validators()) == len(all_validators)
        assert len(v2.registered_validators()) == 1
        assert v1.pipeline is not v2.pipeline


# ===========================================================================
# 2. TestValidationFlow
# ===========================================================================
class TestValidationFlow:
    """Verifies end-to-end orchestration and response contracts for valid and invalid inputs."""

    def test_successful_validation_flow(self) -> None:
        # Arrange
        cfg = InputValidatorConfig()
        validators = create_all_validators(cfg)
        validator = InputValidator(config=cfg, validators=validators)
        ctx = copy.deepcopy(VALID_CONTEXT)

        # Act
        response = validator.validate(VALID_PROMPT, context=ctx)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is True
        assert isinstance(response.results, list)
        assert len(response.results) == len(validator.registered_validators())
        assert all(isinstance(r, ValidationResult) for r in response.results)
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0
        assert all(
            r.timestamp is not None and r.timestamp.tzinfo is not None
            for r in response.results
        )

    def test_failure_flow_empty_prompt(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=False))
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        empty_res = next(
            r for r in response.results if r.validator_name == "EmptyValidator"
        )
        assert empty_res.is_valid is False

    def test_failure_flow_oversized_prompt(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            length=LengthConfig(maximum_length=20),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))
        oversized_prompt = "A" * 50

        # Act
        response = validator.validate(oversized_prompt, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        length_res = next(
            r for r in response.results if r.validator_name == "LengthValidator"
        )
        assert length_res.is_valid is False

    def test_failure_flow_invalid_structured_payload(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            schema=SchemaConfig(
                enable_schema_validation=True,
                required_fields={"missing_field": str},
            ),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        schema_res = next(
            r for r in response.results if r.validator_name == "SchemaValidator"
        )
        assert schema_res.is_valid is False

    def test_failure_flow_unsupported_language(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            language=LanguageConfig(
                supported_languages=["en"], allow_unknown_languages=False
            ),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))
        hindi_prompt = "नमस्ते दुनिया यह एक हिंदी वाक्य validation test के लिए है"

        # Act
        response = validator.validate(hindi_prompt, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        lang_res = next(
            r for r in response.results if r.validator_name == "LanguageValidator"
        )
        assert lang_res.is_valid is False


# ===========================================================================
# 3. TestConfigurationInjection
# ===========================================================================
class TestConfigurationInjection:
    """Verifies that InputValidator respects injected configuration instances."""

    def test_respects_injected_length_config(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            length=LengthConfig(minimum_length=10, maximum_length=30),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate(
            "This prompt exceeds thirty characters in length", context=VALID_CONTEXT
        )

        # Assert
        assert response.is_valid is False
        length_res = next(
            r for r in response.results if r.validator_name == "LengthValidator"
        )
        assert length_res.is_valid is False

    def test_respects_injected_pipeline_config(self) -> None:
        # Arrange
        cfg_fail_fast = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=True))
        validator = InputValidator(
            config=cfg_fail_fast, validators=create_all_validators(cfg_fail_fast)
        )

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == "EmptyValidator"

    def test_respects_injected_language_config(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            language=LanguageConfig(
                supported_languages=["hi", "gu"],
                default_language="hi",
                allow_unknown_languages=False,
            ),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate(
            "This is clearly an English text prompt", context=VALID_CONTEXT
        )

        # Assert
        assert response.is_valid is False
        lang_res = next(
            r for r in response.results if r.validator_name == "LanguageValidator"
        )
        assert lang_res.is_valid is False


# ===========================================================================
# 4. TestPipelineInjection
# ===========================================================================
class TestPipelineInjection:
    """Verifies delegation when a custom ValidationPipeline is injected."""

    def test_delegates_to_injected_pipeline(self) -> None:
        # Arrange
        cfg = InputValidatorConfig()
        validators = create_all_validators(cfg)
        pipeline = ValidationPipeline(
            validators=validators, config=PipelineConfig(fail_fast=True)
        )
        validator = InputValidator(pipeline=pipeline)

        # Act
        response = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert len(response.results) == len(validator.registered_validators())
        assert [r.validator_name for r in response.results] == [
            v.validator_name for v in validator.registered_validators()
        ]
        assert validator.pipeline is pipeline


# ===========================================================================
# 5. TestValidatorManagement
# ===========================================================================
class TestValidatorManagement:
    """Verifies public APIs for registering, unregistering, and listing validators."""

    def test_register_validator(self) -> None:
        # Arrange
        cfg = InputValidatorConfig()
        validator = InputValidator(config=cfg)
        empty_val = EmptyValidator(config=cfg)

        # Act
        validator.register_validator(empty_val)

        # Assert
        registered = validator.registered_validators()
        assert len(registered) == 1
        assert registered[0].validator_name == "EmptyValidator"

    def test_unregister_validator(self) -> None:
        # Arrange
        cfg = InputValidatorConfig()
        validators = create_all_validators(cfg)
        validator = InputValidator(config=cfg, validators=validators)

        # Act
        validator.unregister_validator("LengthValidator")

        # Assert
        registered = validator.registered_validators()
        assert len(registered) == len(validators) - 1
        assert not any(v.validator_name == "LengthValidator" for v in registered)


# ===========================================================================
# 6. TestContextPropagation
# ===========================================================================
class TestContextPropagation:
    """Verifies context dictionary immutability during validation."""

    def test_context_is_not_mutated(self) -> None:
        # Arrange
        original_context = {
            "user": "secops_admin",
            "request_id": "req-998877",
            "nested": {"key": "value"},
        }
        context_snapshot = copy.deepcopy(original_context)
        validator = InputValidator(validators=create_all_validators())

        # Act
        validator.validate(VALID_PROMPT, context=original_context)

        # Assert
        assert original_context == context_snapshot


# ===========================================================================
# 7. TestPromptImmutability
# ===========================================================================
class TestPromptImmutability:
    """Verifies input prompt immutability during validation."""

    def test_prompt_remains_unchanged(self) -> None:
        # Arrange
        prompt = "   Hello World Prompt   "
        prompt_snapshot = prompt
        validator = InputValidator(validators=create_all_validators())

        # Act
        validator.validate(prompt, context=VALID_CONTEXT)

        # Assert
        assert prompt == prompt_snapshot


# ===========================================================================
# 8. TestStatelessness
# ===========================================================================
class TestStatelessness:
    """Verifies that InputValidator remains stateless across multiple executions."""

    def test_repeated_executions_are_stateless_and_deterministic(self) -> None:
        # Arrange
        validator = InputValidator(validators=create_all_validators())

        # Act
        res1 = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)
        res2 = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert res1.is_valid == res2.is_valid
        assert res1 is not res2
        assert res1.results[0] is not res2.results[0]
        assert res1.results[0].metadata is not res2.results[0].metadata


# ===========================================================================
# 9. TestMultipleInstances
# ===========================================================================
class TestMultipleInstances:
    """Verifies isolation and independence between multiple InputValidator instances."""

    def test_multiple_instances_have_no_shared_state(self) -> None:
        # Arrange
        cfg = InputValidatorConfig()
        v1 = InputValidator(config=cfg, validators=create_all_validators(cfg))
        v2 = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        v1.unregister_validator("LengthValidator")

        # Assert
        v1_names = [val.validator_name for val in v1.registered_validators()]
        v2_names = [val.validator_name for val in v2.registered_validators()]

        assert "LengthValidator" not in v1_names
        assert "LengthValidator" in v2_names
        assert len(v1_names) == len(v1.registered_validators())
        assert len(v2_names) == len(v2.registered_validators())


# ===========================================================================
# 10. TestFailFast
# ===========================================================================
class TestFailFast:
    """Verifies pipeline fail-fast execution policy when configured."""

    def test_fail_fast_stops_execution_on_first_failure(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=True))
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == "EmptyValidator"
        assert response.results[0].is_valid is False


# ===========================================================================
# 11. TestFailSafe
# ===========================================================================
class TestFailSafe:
    """Verifies pipeline fail-safe (continue-on-failure) policy when configured."""

    def test_fail_safe_runs_all_validators_despite_failures(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=False))
        validator = InputValidator(config=cfg, validators=create_all_validators(cfg))

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == len(validator.registered_validators())
        failed_names = [r.validator_name for r in response.results if not r.is_valid]
        assert "EmptyValidator" in failed_names


# ===========================================================================
# 12. TestExceptionPropagation
# ===========================================================================
class TestExceptionPropagation:
    """Verifies that public API input boundary errors propagate without absorption."""

    def test_invalid_prompt_type_raises_validation_error(self) -> None:
        # Arrange
        validator = InputValidator()

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(12345, context=VALID_CONTEXT)  # type: ignore[arg-type]

        assert "Prompt parameter must be a string" in str(exc_info.value)
