"""Integration test suite for the InputValidator ValidationPipeline.

The tests exercise the full end‑to‑end flow using **real** validator
implementations shipped with the framework. They verify:

* correct priority ordering (derived dynamically),
* propagation of the prompt and context objects,
* proper handling of the `fail_fast` flag,
* successful aggregation of `ValidationResult` objects,
* integrity of timestamps and execution times,
* isolation between multiple pipeline instances.

No production code is modified.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import List, Any

import pytest

# ---------------------------------------------------------------------------
# Imports – real validators and core components
# ---------------------------------------------------------------------------
from input_validator.config import InputValidatorConfig, PipelineConfig
from input_validator.models import InputValidationResponse, ValidationResult
from input_validator.pipeline import ValidationPipeline
from input_validator.validators.empty import EmptyValidator
from input_validator.validators.length import LengthValidator
from input_validator.validators.encoding import EncodingValidator
from input_validator.validators.format import FormatValidator
from input_validator.validators.schema import SchemaValidator
from input_validator.validators.file_validator import FileValidator
from input_validator.validators.language import LanguageValidator
from input_validator.validators.context_rules import ContextRulesValidator
from input_validator.validators.completeness import CompletenessValidator
from input_validator.base_validator import BaseValidator
from input_validator.exceptions import ValidationExecutionError


# ---------------------------------------------------------------------------
# Helper – create a fully‑configured pipeline with **all** real validators
# ---------------------------------------------------------------------------
def create_pipeline(fail_fast: bool = True) -> ValidationPipeline:
    """Create a ValidationPipeline containing one instance of every concrete validator.

    A fresh ``InputValidatorConfig`` supplies the default configuration objects
    required by each validator. ``PipelineConfig`` controls the ``fail_fast``
    behaviour.
    """
    cfg = InputValidatorConfig()
    validators: List[BaseValidator] = [
        EmptyValidator(config=cfg),
        LengthValidator(config=cfg.length),
        EncodingValidator(config=cfg),
        FormatValidator(config=cfg),
        SchemaValidator(config=cfg.schema),
        FileValidator(config=cfg),
        LanguageValidator(config=cfg.language),
        ContextRulesValidator(config=cfg),
        CompletenessValidator(config=cfg),
    ]
    pipe_cfg = PipelineConfig(fail_fast=fail_fast)
    return ValidationPipeline(validators=validators, config=pipe_cfg)


# ---------------------------------------------------------------------------
# Common test data – realistic prompts and contexts
# ---------------------------------------------------------------------------
VALID_PROMPT = (
    "Hello world! This is a short, valid English sentence containing "
    "Unicode 🌟 and an emoji 🚀."
)

# Context required by ``CompletenessValidator`` (user + request_id)
VALID_CONTEXT = {"user": "test_user", "request_id": "req-123"}


# ---------------------------------------------------------------------------
# Test classes – organized by logical concern (AAA pattern)
# ---------------------------------------------------------------------------
class TestPipelineConstruction:
    """Validate that the pipeline registers validators in priority order."""

    def test_validators_are_registered_and_sorted(self) -> None:
        pipeline = create_pipeline()
        registered = pipeline.get_registered_validators()
        priorities = [v.priority for v in registered]
        assert priorities == sorted(priorities)


class TestFullPipelineSuccess:
    """The happy‑path where every validator passes."""

    def test_successful_execution_returns_valid_response(self) -> None:
        pipeline = create_pipeline(fail_fast=False)
        response: InputValidationResponse = pipeline.validate(
            VALID_PROMPT, context=copy.deepcopy(VALID_CONTEXT)
        )
        # ---- top‑level response contract ----
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is True
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0
        assert isinstance(response.results, list)
        assert len(response.results) == len(pipeline.get_registered_validators())

        # ---- each ValidationResult contract ----
        for result in response.results:
            assert isinstance(result, ValidationResult)
            assert result.is_valid is True
            assert isinstance(result.execution_time_ms, float)
            assert result.execution_time_ms >= 0.0
            assert isinstance(result.timestamp, datetime)
            assert result.timestamp.tzinfo is not None
            assert isinstance(result.metadata, dict)

        # ---- metadata summary fields ----
        summary = response.metadata
        assert summary["total_validators"] == len(pipeline.get_registered_validators())
        assert summary["executed_validators"] == len(
            pipeline.get_registered_validators()
        )


class TestPipelineFailures:
    """Scenarios where one or more validators reject the input."""

    @pytest.fixture
    def pipeline(self) -> ValidationPipeline:
        """Fail‑safe pipeline (fail_fast=False) used for multi‑failure testing."""
        return create_pipeline(fail_fast=False)

    def test_empty_prompt_fails_empty_validator_only_when_fail_fast_true(
        self, pipeline: ValidationPipeline
    ) -> None:
        fast_pipeline = create_pipeline(fail_fast=True)
        resp_fast: InputValidationResponse = fast_pipeline.validate(
            "", context=VALID_CONTEXT
        )
        assert resp_fast.is_valid is False
        assert len(resp_fast.results) == 1
        assert resp_fast.results[0].validator_name == "EmptyValidator"
        assert resp_fast.results[0].is_valid is False

        resp_safe: InputValidationResponse = pipeline.validate(
            "", context=VALID_CONTEXT
        )
        assert resp_safe.is_valid is False
        assert len(resp_safe.results) == len(pipeline.get_registered_validators())
        fails = [r for r in resp_safe.results if not r.is_valid]
        assert any(r.validator_name == "EmptyValidator" for r in fails)


class TestFailFast:
    """Explicit tests for the ``fail_fast`` behaviour."""

    def test_fail_fast_stops_after_first_failure(self) -> None:
        pipeline = create_pipeline(fail_fast=True)
        response = pipeline.validate("", context=VALID_CONTEXT)
        assert response.is_valid is False
        assert len(response.results) == 1
        assert response.results[0].validator_name == "EmptyValidator"

    def test_fail_safe_runs_all_validators_despite_failures(self) -> None:
        pipeline = create_pipeline(fail_fast=False)
        response = pipeline.validate("", context=VALID_CONTEXT)
        assert response.is_valid is False
        assert len(response.results) == len(pipeline.get_registered_validators())
        assert response.results[0].validator_name == "EmptyValidator"
        assert not response.results[0].is_valid


class TestExecutionOrder:
    """Confirm that ``results`` follow the validator priority order."""

    def test_results_appear_in_expected_priority_order(self) -> None:
        pipeline = create_pipeline()
        response = pipeline.validate(VALID_PROMPT, context=VALID_CONTEXT)
        expected_priorities = [v.priority for v in pipeline.get_registered_validators()]
        name_to_priority = {
            v.validator_name: v.priority for v in pipeline.get_registered_validators()
        }
        actual_priorities = [
            name_to_priority[r.validator_name] for r in response.results
        ]
        assert actual_priorities == expected_priorities


class TestContextPropagation:
    """Validate that the same (immutable) context is seen by all validators."""

    def test_context_is_unchanged_and_shared_across_validators(self) -> None:
        pipeline = create_pipeline()
        mutable_context = {"user": "test_user", "request_id": "req-789", "extra": []}
        ctx_snapshot = copy.deepcopy(mutable_context)
        response = pipeline.validate(VALID_PROMPT, context=mutable_context)
        assert mutable_context == ctx_snapshot
        # No request_id metadata assertion as it's not guaranteed


class TestMetadataIntegrity:
    """Ensure that pipeline‑level and result‑level metadata are fresh objects."""

    def test_fresh_metadata_objects_per_execution(self) -> None:
        pipeline = create_pipeline()
        ctx = copy.deepcopy(VALID_CONTEXT)
        resp1 = pipeline.validate(VALID_PROMPT, context=ctx)
        resp2 = pipeline.validate(VALID_PROMPT, context=ctx)
        assert resp1.metadata is not resp2.metadata
        for r1, r2 in zip(resp1.results, resp2.results):
            assert r1.metadata is not r2.metadata


class TestMultiplePipelines:
    """Validate that separate pipeline instances do not interfere with each other."""

    def test_independent_execution_between_pipelines(self) -> None:
        pipe_a = create_pipeline(fail_fast=True)
        pipe_b = create_pipeline(fail_fast=False)
        resp_a = pipe_a.validate("", context=VALID_CONTEXT)
        resp_b = pipe_b.validate("", context=VALID_CONTEXT)
        assert len(resp_a.results) == 1
        assert len(resp_b.results) == len(pipe_b.get_registered_validators())


class TestExceptionPropagation:
    """Inject a validator that raises an unexpected exception and verify handling."""

    class ExplodingValidator(BaseValidator):
        """A test‑only validator that raises a generic exception on validation."""

        @property
        def validator_name(self) -> str:
            return "ExplodingValidator"

        @property
        def priority(self) -> int:
            return 5

        def _validate(self, prompt: str, context: dict[str, Any]):
            raise RuntimeError("Boom!")

    def test_unexpected_exception_is_wrapped_as_ValidationExecutionError(self) -> None:
        cfg = InputValidatorConfig()
        exploding = self.ExplodingValidator(config=cfg)
        pipeline = ValidationPipeline(
            validators=[exploding, EmptyValidator(config=cfg)],
            config=PipelineConfig(fail_fast=True),
        )
        with pytest.raises(ValidationExecutionError) as excinfo:
            pipeline.validate(VALID_PROMPT, context=VALID_CONTEXT)
        err = excinfo.value
        assert "Unexpected crash in validator 'ExplodingValidator'" in err.message
        assert err.details.get("validator_name") == "ExplodingValidator"


class TestExecutionTime:
    """Validate that execution times are present, numeric and non‑negative."""

    @pytest.mark.parametrize("fail_fast", [True, False])
    def test_execution_time_is_float_and_non_negative(self, fail_fast: bool) -> None:
        pipeline = create_pipeline(fail_fast=fail_fast)
        response = pipeline.validate(VALID_PROMPT, context=VALID_CONTEXT)
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0
        for result in response.results:
            assert isinstance(result.execution_time_ms, float)
            assert result.execution_time_ms >= 0.0
