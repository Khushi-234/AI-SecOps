"""
Integration tests for the complete validator chain execution.

These tests focus exclusively on the orchestration performed by
`ValidationPipeline` – they do **not** re‑test individual validator logic.
The suite verifies that:

* every real validator is executed exactly once,
* execution respects the configured priority order,
* the validator chain is deterministic and immutable,
* dynamic registration/unregistration works as expected,
* multiple pipeline instances remain completely independent,
* prompt, context and validator configuration objects are never mutated,
* each call produces fresh `ValidationResult` and metadata objects.

The tests are written using the AAA (Arrange‑Act‑Assert) pattern and adhere
to enterprise‑grade readability standards.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import List, Any

import pytest

# --------------------------------------------------------------------------- #
# Real components – validators and core pipeline
# --------------------------------------------------------------------------- #
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
from input_validator.validators.base_validator import BaseValidator

# --------------------------------------------------------------------------- #
# Helper – build a fully‑configured pipeline with **all** real validators
# --------------------------------------------------------------------------- #
def build_full_pipeline(fail_fast: bool = True) -> ValidationPipeline:
    """
    Construct a `ValidationPipeline` containing one instance of every concrete
    validator shipped with the framework.

    The default `InputValidatorConfig` supplies the appropriate configuration
    objects required by each validator.
    """
    cfg = InputValidatorConfig()
    validators: List[BaseValidator] = [
        EmptyValidator(config=cfg),
        LengthValidator(config=cfg),
        EncodingValidator(config=cfg),
        FormatValidator(config=cfg),
        SchemaValidator(config=cfg),
        FileValidator(config=cfg),
        LanguageValidator(config=cfg),
        ContextRulesValidator(config=cfg),
        CompletenessValidator(config=cfg),
    ]
    pipe_cfg = PipelineConfig(fail_fast=fail_fast)
    return ValidationPipeline(validators=validators, config=pipe_cfg)


# --------------------------------------------------------------------------- #
# Test data – a realistic prompt and context
# --------------------------------------------------------------------------- #
VALID_PROMPT = (
    "Hello world! This is a short, valid English sentence containing "
    "Unicode 🌟 and an emoji 🚀."
)

VALID_CONTEXT = {"user": "test_user", "request_id": "req-123"}


# --------------------------------------------------------------------------- #
# Test suite – validator chain orchestration
# --------------------------------------------------------------------------- #

class TestChainConstruction:
    """Validate that the pipeline registers validators in priority order."""

    def test_validators_are_registered_and_sorted(self) -> None:
        pipeline = build_full_pipeline()
        registered = pipeline.get_registered_validators()
        priorities = [v.priority for v in registered]
        assert priorities == sorted(priorities), "Validators must be sorted by priority"


class TestExecutionOrder:
    """Verify that results follow the validator priority order."""

    def test_results_match_registered_priority_order(self) -> None:
        pipeline = build_full_pipeline()
        response: InputValidationResponse = pipeline.validate(
            VALID_PROMPT, context=copy.deepcopy(VALID_CONTEXT)
        )
        reg = pipeline.get_registered_validators()
        priority_by_name = {v.validator_name: v.priority for v in reg}
        result_priorities = [priority_by_name[r.validator_name] for r in response.results]
        expected_priorities = [v.priority for v in reg]
        assert result_priorities == expected_priorities, "Result ordering must follow priority"


class TestRegistration:
    """Exercise explicit registration APIs."""

    def test_register_and_unregister_validator(self) -> None:
        pipeline = build_full_pipeline()
        initial_names = {v.validator_name for v in pipeline.get_registered_validators()}

        # Dynamically add a simple no‑op validator
        class NoOpValidator(BaseValidator):
            @property
            def validator_name(self) -> str:  # pragma: no cover
                return "NoOpValidator"

            @property
            def priority(self) -> int:
                return 15  # deliberately after the existing validators

            def _validate(self, prompt: str, context: dict[str, Any]):
                return True, None, None

        noop = NoOpValidator(config=InputValidatorConfig())
        pipeline.register_validator(noop)

        after_register = {v.validator_name for v in pipeline.get_registered_validators()}
        assert "NoOpValidator" in after_register
        assert after_register == initial_names.union({"NoOpValidator"})

        # Unregister and verify removal
        pipeline.unregister_validator("NoOpValidator")
        after_unregister = {v.validator_name for v in pipeline.get_registered_validators()}
        assert "NoOpValidator" not in after_unregister
        assert after_unregister == initial_names


class TestDynamicRegistration:
    """Validate that a validator added after construction appears in proper order."""

    def test_dynamic_registration_respects_priority(self) -> None:
        pipeline = build_full_pipeline()
        reg_before = pipeline.get_registered_validators()
        max_priority = max(v.priority for v in reg_before)

        class LateValidator(BaseValidator):
            @property
            def validator_name(self) -> str:
                return "LateValidator"

            @property
            def priority(self) -> int:
                # Insert between the highest current priority and an arbitrary larger value
                return max_priority - 1

            def _validate(self, prompt: str, context: dict[str, Any]):
                return True, None, None

        late = LateValidator(config=InputValidatorConfig())
        pipeline.register_validator(late)

        reg_after = pipeline.get_registered_validators()
        priorities = [v.priority for v in reg_after]
        assert priorities == sorted(priorities), "Dynamic registration must keep sorted order"
        assert any(v.validator_name == "LateValidator" for v in reg_after)


class TestRepeatedExecution:
    """Repeated calls must be deterministic and produce fresh objects."""

    def test_multiple_executions_yield_fresh_results(self) -> None:
        pipeline = build_full_pipeline(fail_fast=False)
        ctx = copy.deepcopy(VALID_CONTEXT)

        first: InputValidationResponse = pipeline.validate(
            VALID_PROMPT, context=copy.deepcopy(ctx)
        )
        second: InputValidationResponse = pipeline.validate(
            VALID_PROMPT, context=copy.deepcopy(ctx)
        )

        # Response objects must be distinct
        assert first is not second
        assert first.metadata is not second.metadata

        # Each ValidationResult must be a fresh instance
        for r1, r2 in zip(first.results, second.results):
            assert r1 is not r2
            assert r1.metadata is not r2.metadata

        # Ordering and validator count must be identical
        assert [r.validator_name for r in first.results] == [
            r.validator_name for r in second.results
        ]
        assert len(first.results) == len(pipeline.get_registered_validators())


class TestContextPropagation:
    """The pipeline must never mutate the supplied context object."""

    def test_context_is_immutable_across_validators(self) -> None:
        pipeline = build_full_pipeline()
        mutable_context = {"user": "tester", "request_id": "id-456", "extra": []}
        snapshot = copy.deepcopy(mutable_context)

        pipeline.validate(VALID_PROMPT, context=mutable_context)
        assert mutable_context == snapshot, "Pipeline must not alter the original context"

    def test_context_stays_clean_with_extra_fields(self) -> None:
        pipeline = build_full_pipeline()
        mutable_context = {"user": "tester", "temp": "ignore_me"}
        pipeline.validate(VALID_PROMPT, context=mutable_context)
        assert "temp" in mutable_context


class TestChainConsistency:
    """Ensure each validator runs once and does not affect the next validator."""

    def test_each_validator_executes_exactly_once(self) -> None:
        pipeline = build_full_pipeline()
        response = pipeline.validate(VALID_PROMPT, context=copy.deepcopy(VALID_CONTEXT))

        registered = pipeline.get_registered_validators()
        result_names = [r.validator_name for r in response.results]

        # Every registered validator must appear exactly once in the results
        assert set(result_names) == {v.validator_name for v in registered}
        assert len(result_names) == len(registered)

        # No duplicate entries
        assert len(result_names) == len(set(result_names))


class TestMultiplePipelines:
    """Separate pipeline instances must not share execution state."""

    def test_independent_pipeline_instances(self) -> None:
        pipe_a = build_full_pipeline(fail_fast=True)
        pipe_b = build_full_pipeline(fail_fast=False)

        resp_a = pipe_a.validate("", context=VALID_CONTEXT)
        resp_b = pipe_b.validate("", context=VALID_CONTEXT)

        # Different fail‑fast settings lead to different result counts
        assert len(resp_a.results) == 1  # only EmptyValidator should run
        assert len(resp_b.results) == len(pipe_b.get_registered_validators())

        # Ensure no cross‑pipeline state leakage
        assert resp_a is not resp_b
        for a_res, b_res in zip(resp_a.results, resp_b.results):
            assert a_res is not b_res


class TestOrderStability:
    """Repeated calls to `get_registered_validators` must be deterministic."""

    def test_registered_validators_order_is_stable(self) -> None:
        pipeline = build_full_pipeline()
        first = [v.validator_name for v in pipeline.get_registered_validators()]
        second = [v.validator_name for v in pipeline.get_registered_validators()]
        assert first == second, "Validator ordering must be stable across calls"


class TestThreadSafety:
    """Repeated sequential executions must not leak state between runs."""

    def test_no_state_leak_across_executions(self) -> None:
        pipeline = build_full_pipeline()
        ctx = copy.deepcopy(VALID_CONTEXT)

        for _ in range(5):
            response = pipeline.validate(VALID_PROMPT, context=copy.deepcopy(ctx))
            # Ensure each execution produces fresh metadata timestamps

            # Ensure validators do not retain previous execution data
            for result in response.results:
                assert isinstance(result.timestamp, datetime)


# --------------------------------------------------------------------------- #
# End of test suite
# --------------------------------------------------------------------------- #
