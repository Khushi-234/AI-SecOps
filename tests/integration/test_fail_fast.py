"""
Integration test suite for ValidationPipeline fail-fast and fail-safe execution policies.

This test suite focuses exclusively on the execution strategy of ValidationPipeline:
    - Fail-Fast mode (fail_fast=True): Halts validator execution immediately upon
      encountering the first validation failure.
    - Fail-Safe mode (fail_fast=False): Continues executing all registered validators
      regardless of intermediate failures.

All tests utilize ONLY real production components and concrete validators, ensuring
deterministic execution, context/prompt immutability, and strict adherence to the
Arrange-Act-Assert (AAA) pattern.
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
VALID_PROMPT = "Hello world! This is a valid English sentence used to test pipeline execution policies."

VALID_CONTEXT = {
    "user": "secops_admin",
    "request_id": "req-112233",
}


def build_validators(cfg: InputValidatorConfig | None = None) -> list[BaseValidator]:
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


def build_pipeline(
    fail_fast: bool = True, cfg: InputValidatorConfig | None = None
) -> ValidationPipeline:
    """
    Helper function to build a ValidationPipeline loaded with all real production validators.
    """
    config = cfg or InputValidatorConfig()
    pipe_cfg = PipelineConfig(fail_fast=fail_fast)
    return ValidationPipeline(validators=build_validators(config), config=pipe_cfg)


# ===========================================================================
# 1. TestFailFastExecution
# ===========================================================================
class TestFailFastExecution:
    """Verifies that fail_fast=True halts execution immediately at the first failing validator."""

    def test_empty_prompt_halts_at_first_validator(self) -> None:
        # Arrange
        pipeline = build_pipeline(fail_fast=True)

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == "EmptyValidator"
        assert response.results[0].is_valid is False

    def test_oversized_prompt_halts_at_length_validator(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(length=LengthConfig(maximum_length=15))
        pipeline = build_pipeline(fail_fast=True, cfg=cfg)
        oversized_prompt = "This prompt is longer than fifteen characters."
        registered = pipeline.get_registered_validators()
        length_val_idx = next(
            i for i, v in enumerate(registered) if v.validator_name == "LengthValidator"
        )

        # Act
        response = pipeline.validate(oversized_prompt, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        assert len(response.results) == length_val_idx + 1
        assert response.results[-1].validator_name == "LengthValidator"
        assert response.results[-1].is_valid is False
        assert all(r.is_valid is True for r in response.results[:-1])

    def test_invalid_schema_halts_at_schema_validator(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(
            schema=SchemaConfig(
                enable_schema_validation=True,
                required_fields={"mandatory_field": str},
            )
        )
        pipeline = build_pipeline(fail_fast=True, cfg=cfg)
        registered = pipeline.get_registered_validators()
        schema_val_idx = next(
            i for i, v in enumerate(registered) if v.validator_name == "SchemaValidator"
        )

        # Act
        response = pipeline.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        assert len(response.results) == schema_val_idx + 1
        assert response.results[-1].validator_name == "SchemaValidator"
        assert response.results[-1].is_valid is False
        assert all(r.is_valid is True for r in response.results[:-1])


# ===========================================================================
# 2. TestFailSafeExecution
# ===========================================================================
class TestFailSafeExecution:
    """Verifies that fail_fast=False executes all registered validators despite failures."""

    def test_all_validators_execute_on_empty_prompt(self) -> None:
        # Arrange
        pipeline = build_pipeline(fail_fast=False)
        total_registered = len(pipeline.get_registered_validators())

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is False
        assert len(response.results) == total_registered
        assert response.results[0].validator_name == "EmptyValidator"
        assert response.results[0].is_valid is False

    def test_all_validators_contribute_results_for_valid_prompt(self) -> None:
        # Arrange
        pipeline = build_pipeline(fail_fast=False)
        total_registered = len(pipeline.get_registered_validators())

        # Act
        response = pipeline.validate(VALID_PROMPT, context=VALID_CONTEXT)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is True
        assert len(response.results) == total_registered
        assert all(r.is_valid is True for r in response.results)
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0


# ===========================================================================
# 3. TestExecutionOrder
# ===========================================================================
class TestExecutionOrder:
    """Verifies priority-ordered execution and failure stopping points."""

    def test_first_failure_determines_stopping_point_dynamically(self) -> None:
        # Arrange
        cfg = InputValidatorConfig(length=LengthConfig(maximum_length=10))
        pipeline = build_pipeline(fail_fast=True, cfg=cfg)
        registered = pipeline.get_registered_validators()

        # Act
        response = pipeline.validate("A" * 20, context=VALID_CONTEXT)

        # Assert: Dynamically locate LengthValidator position
        expected_index = next(
            i for i, v in enumerate(registered) if v.validator_name == "LengthValidator"
        )
        assert len(response.results) == expected_index + 1
        assert (
            response.results[-1].validator_name
            == registered[expected_index].validator_name
        )
        assert response.results[-1].is_valid is False


# ===========================================================================
# 4. TestMultipleFailures
# ===========================================================================
class TestMultipleFailures:
    """Verifies handling of inputs that trigger multiple failing validators."""

    def test_fail_fast_returns_only_first_failure_for_multi_failing_input(self) -> None:
        # Arrange: Empty prompt + missing required fields in schema
        cfg = InputValidatorConfig(
            schema=SchemaConfig(
                enable_schema_validation=True,
                required_fields={"missing_key": str},
            )
        )
        pipeline = build_pipeline(fail_fast=True, cfg=cfg)

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert: Fails fast at EmptyValidator (priority 10)
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == "EmptyValidator"

    def test_fail_safe_returns_all_failures_for_multi_failing_input(self) -> None:
        # Arrange: Empty prompt + schema failure
        cfg = InputValidatorConfig(
            schema=SchemaConfig(
                enable_schema_validation=True,
                required_fields={"missing_key": str},
            )
        )
        pipeline = build_pipeline(fail_fast=False, cfg=cfg)
        total_registered = len(pipeline.get_registered_validators())

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert: All validators execute, multiple failures collected
        assert response.is_valid is False
        assert len(response.results) == total_registered
        failed_names = [r.validator_name for r in response.results if not r.is_valid]
        assert "EmptyValidator" in failed_names
        assert "SchemaValidator" in failed_names
        assert len(failed_names) >= 2


# ===========================================================================
# 5. TestConfiguration
# ===========================================================================
class TestConfiguration:
    """Verifies pipeline behavior under distinct PipelineConfig configurations."""

    def test_pipeline_respects_fail_fast_true_configuration(self) -> None:
        # Arrange
        pipe_cfg = PipelineConfig(fail_fast=True)
        pipeline = ValidationPipeline(validators=build_validators(), config=pipe_cfg)

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == 1

    def test_pipeline_respects_fail_fast_false_configuration(self) -> None:
        # Arrange
        pipe_cfg = PipelineConfig(fail_fast=False)
        pipeline = ValidationPipeline(validators=build_validators(), config=pipe_cfg)

        # Act
        response = pipeline.validate("", context=VALID_CONTEXT)

        # Assert
        assert response.is_valid is False
        assert len(response.results) == len(pipeline.get_registered_validators())


# ===========================================================================
# 6. TestRepeatedExecution
# ===========================================================================
class TestRepeatedExecution:
    """Verifies deterministic and stateless behavior across repeated runs."""

    def test_deterministic_fail_fast_execution(self) -> None:
        # Arrange
        pipeline = build_pipeline(fail_fast=True)

        # Act
        responses = [pipeline.validate("", context=VALID_CONTEXT) for _ in range(5)]

        # Assert
        for resp in responses:
            assert resp.is_valid is False
            assert len(resp.results) == 1
            assert resp.results[0].validator_name == "EmptyValidator"

    def test_statelessness_between_fail_fast_and_fail_safe_runs(self) -> None:
        # Arrange
        pipeline_fast = build_pipeline(fail_fast=True)
        pipeline_safe = build_pipeline(fail_fast=False)

        # Act
        resp_fast = pipeline_fast.validate("", context=VALID_CONTEXT)
        resp_safe = pipeline_safe.validate("", context=VALID_CONTEXT)

        # Assert: Run results are independent and distinct
        assert len(resp_fast.results) == 1
        assert len(resp_safe.results) == len(pipeline_safe.get_registered_validators())
        assert resp_fast.results[0] is not resp_safe.results[0]


# ===========================================================================
# 7. TestContextImmutability
# ===========================================================================
class TestContextImmutability:
    """Verifies that context payloads are never mutated during execution."""

    def test_context_is_never_modified_during_fail_fast_execution(self) -> None:
        # Arrange
        context = {"user": "secops_admin", "request_id": "req-999", "meta": {"a": 1}}
        context_copy = copy.deepcopy(context)
        pipeline = build_pipeline(fail_fast=True)

        # Act
        pipeline.validate(VALID_PROMPT, context=context)

        # Assert
        assert context == context_copy


# ===========================================================================
# 8. TestPromptImmutability
# ===========================================================================
class TestPromptImmutability:
    """Verifies that prompt strings are never mutated during execution."""

    def test_prompt_is_never_modified_during_fail_fast_execution(self) -> None:
        # Arrange
        prompt = "  Whitespace Surrounded Prompt  "
        prompt_snapshot = prompt
        pipeline = build_pipeline(fail_fast=True)

        # Act
        pipeline.validate(prompt, context=VALID_CONTEXT)

        # Assert
        assert prompt == prompt_snapshot
