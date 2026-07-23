"""
End-to-end integration test suite for the complete Input Validator framework.

This suite represents the highest-level integration test of Sprint 6. It verifies the
entire orchestration lifecycle across all production modules:
    Client Call -> InputValidator -> ValidationPipeline -> Priority-ordered Validators
    -> ValidationResult objects -> InputValidationResponse.

Key framework behavior verified:
    - Full end-to-end orchestration using ONLY real concrete validators and configurations.
    - End-to-end success and failure validation flows.
    - InputValidationResponse and ValidationResult contract boundaries.
    - Priority-based dynamic execution order.
    - Injected configuration governance (LengthConfig, LanguageConfig, PipelineConfig).
    - Immutability of input prompts and context payloads.
    - Statelessness and isolation across repeated calls and multiple instances.
    - Exception safety under invalid API argument usage.
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
    "Hello world! This is a valid English sentence testing full framework integration."
)

VALID_CONTEXT = {
    "user": "secops_admin",
    "request_id": "req-e2e-998877",
}


def create_all_validators(
    cfg: InputValidatorConfig | None = None,
) -> list[BaseValidator]:
    """
    Instantiates all concrete production validators with matching sub-configurations.
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


def create_validator_facade(
    cfg: InputValidatorConfig | None = None,
) -> InputValidator:
    """
    Helper function to instantiate an InputValidator facade populated with all real validators.
    """
    config = cfg or InputValidatorConfig()
    return InputValidator(config=config, validators=create_all_validators(config))


# ===========================================================================
# 1. TestEndToEndValidation
# ===========================================================================
class TestEndToEndValidation:
    """Verifies complete end-to-end orchestration through the public InputValidator facade."""

    def test_complete_end_to_end_validation_pipeline_orchestration(self) -> None:
        # Arrange
        validator = create_validator_facade()
        ctx = copy.deepcopy(VALID_CONTEXT)

        # Act
        response = validator.validate(VALID_PROMPT, context=ctx)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert isinstance(response.results, list)
        assert len(response.results) == len(validator.registered_validators())
        assert all(isinstance(r, ValidationResult) for r in response.results)


# ===========================================================================
# 2. TestSuccessfulFlow
# ===========================================================================
class TestSuccessfulFlow:
    """Verifies complete happy-path execution flow for valid prompt and context inputs."""

    def test_successful_prompt_validation_flow(self) -> None:
        # Arrange
        validator = create_validator_facade()
        ctx = copy.deepcopy(VALID_CONTEXT)

        # Act
        response = validator.validate(VALID_PROMPT, context=ctx)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is True
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0
        assert all(
            r.timestamp is not None and r.timestamp.tzinfo is not None
            for r in response.results
        )


# ===========================================================================
# 3. TestFailureFlow
# ===========================================================================
class TestFailureFlow:
    """Verifies framework resilience and failure result aggregation across invalid inputs."""

    def test_failure_flow_empty_prompt(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=False))
        validator = create_validator_facade(cfg)

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        assert any(not r.is_valid for r in response.results)

    def test_failure_flow_oversized_prompt(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            length=LengthConfig(maximum_length=20),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = create_validator_facade(cfg)
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

    def test_failure_flow_unsupported_language(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            language=LanguageConfig(
                supported_languages=["en"], allow_unknown_languages=False
            ),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = create_validator_facade(cfg)
        hindi_prompt = "नमस्ते दुनिया यह एक हिंदी वाक्य validation flow test के लिए है"

        # Act
        response = validator.validate(hindi_prompt, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        lang_res = next(
            r for r in response.results if r.validator_name == "LanguageValidator"
        )
        assert lang_res.is_valid is False

    def test_failure_flow_schema_validation_failure(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            schema=SchemaConfig(
                enable_schema_validation=True,
                required_fields={"required_payload_key": str},
            ),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = create_validator_facade(cfg)

        # Act
        response = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        schema_res = next(
            r for r in response.results if r.validator_name == "SchemaValidator"
        )
        assert schema_res.is_valid is False


# ===========================================================================
# 4. TestResponseContract
# ===========================================================================
class TestResponseContract:
    """Verifies strict adherence to InputValidationResponse and ValidationResult schemas."""

    def test_response_and_result_dataclass_contracts(self) -> None:
        # Arrange
        validator = create_validator_facade()

        # Act
        response = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert: InputValidationResponse structure
        assert hasattr(response, "is_valid") and isinstance(response.is_valid, bool)
        assert hasattr(response, "results") and isinstance(response.results, list)
        assert hasattr(response, "execution_time_ms") and isinstance(
            response.execution_time_ms, float
        )
        assert hasattr(response, "metadata") and isinstance(response.metadata, dict)

        # Assert: ValidationResult structures
        for result in response.results:
            assert hasattr(result, "validator_name") and isinstance(
                result.validator_name, str
            )
            assert hasattr(result, "is_valid") and isinstance(result.is_valid, bool)
            assert hasattr(result, "execution_time_ms") and isinstance(
                result.execution_time_ms, float
            )
            assert hasattr(result, "timestamp") and result.timestamp is not None
            assert hasattr(result, "metadata") and isinstance(result.metadata, dict)


# ===========================================================================
# 5. TestExecutionOrder
# ===========================================================================
class TestExecutionOrder:
    """Verifies that execution order is derived dynamically from validator priorities."""

    def test_execution_order_derived_dynamically_from_priorities(self) -> None:
        # Arrange
        validator = create_validator_facade()
        registered = validator.registered_validators()
        name_to_priority = {v.validator_name: v.priority for v in registered}

        # Act
        response = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        actual_priorities = [
            name_to_priority[r.validator_name] for r in response.results
        ]
        assert actual_priorities == sorted(actual_priorities)


# ===========================================================================
# 6. TestConfigurationIntegration
# ===========================================================================
class TestConfigurationIntegration:
    """Verifies end-to-end integration with custom injected configuration objects."""

    def test_custom_length_configuration(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            length=LengthConfig(minimum_length=5, maximum_length=25),
            pipeline=PipelineConfig(fail_fast=False),
        )
        validator = create_validator_facade(cfg)

        # Act
        response = validator.validate(
            "This prompt text exceeds twenty-five characters", context=VALID_CONTEXT
        )

        # Assert
        assert response.is_valid is False
        length_res = next(
            r for r in response.results if r.validator_name == "LengthValidator"
        )
        assert length_res.is_valid is False

    def test_custom_pipeline_fail_fast_configuration(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=True))
        validator = create_validator_facade(cfg)
        expected_first_validator = validator.registered_validators()[0].validator_name

        # Act
        response = validator.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == expected_first_validator


# ===========================================================================
# 7. TestRepeatedExecution
# ===========================================================================
class TestRepeatedExecution:
    """Verifies deterministic behavior and fresh object instantiation across repeated runs."""

    def test_repeated_executions_produce_fresh_deterministic_objects(self) -> None:
        # Arrange
        validator = create_validator_facade()

        # Act
        res1 = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)
        res2 = validator.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert res1.is_valid == res2.is_valid
        assert res1 is not res2
        assert res1.results[0] is not res2.results[0]
        assert res1.results[0].metadata is not res2.results[0].metadata


# ===========================================================================
# 8. TestMultipleInstances
# ===========================================================================
class TestMultipleInstances:
    """Verifies isolation and absence of shared state between facade instances."""

    def test_independent_facade_instances_isolate_state(self) -> None:
        # Arrange
        v1 = create_validator_facade()
        v2 = create_validator_facade()

        # Act
        v1.unregister_validator("LengthValidator")

        # Assert
        v1_names = [v.validator_name for v in v1.registered_validators()]
        v2_names = [v.validator_name for v in v2.registered_validators()]

        assert "LengthValidator" not in v1_names
        assert "LengthValidator" in v2_names
        assert len(v1_names) == len(v2_names) - 1


# ===========================================================================
# 9. TestContextHandling
# ===========================================================================
class TestContextHandling:
    """Verifies context acceptance and immutability during full workflow execution."""

    def test_context_accepted_and_never_mutated(self) -> None:
        # Arrange
        context = {
            "user": "secops_admin",
            "request_id": "req-998877",
            "meta": {"nested": "value"},
        }
        context_snapshot = copy.deepcopy(context)
        validator = create_validator_facade()

        # Act
        response = validator.validate(VALID_PROMPT, context=context)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert context == context_snapshot


# ===========================================================================
# 10. TestPromptImmutability
# ===========================================================================
class TestPromptImmutability:
    """Verifies prompt string immutability during full workflow execution."""

    def test_original_prompt_string_remains_unmodified(self) -> None:
        # Arrange
        prompt = "   Hello Enterprise Prompt   "
        prompt_snapshot = prompt
        validator = create_validator_facade()

        # Act
        validator.validate(prompt, context=VALID_CONTEXT)

        # Assert
        assert prompt == prompt_snapshot


# ===========================================================================
# 11. TestExceptionSafety
# ===========================================================================
class TestExceptionSafety:
    """Verifies that invalid API arguments propagate production boundary exceptions."""

    def test_invalid_prompt_type_raises_validation_error(self) -> None:
        # Arrange
        validator = create_validator_facade()

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(998877, context=VALID_CONTEXT)  # type: ignore[arg-type]

        assert "Prompt parameter must be a string" in str(exc_info.value)
