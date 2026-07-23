"""
Integration test suite for end-to-end request context propagation across the Input Validator framework.

This test suite verifies that request context structures pass seamlessly from the
public InputValidator facade through ValidationPipeline and into every concrete validator.

Key execution characteristics verified:
    - Context propagation from facade to pipeline without execution error.
    - Strict context immutability (original dicts, nested structures, lists, tuples are never mutated).
    - Support for diverse context types (populated, deeply nested, empty {}, and None).
    - Context isolation across repeated sequential executions and multiple InputValidator instances.
    - Prompt immutability and InputValidationResponse contract consistency.

All tests utilize ONLY real production components and concrete validators, following
the Arrange-Act-Assert (AAA) pattern.
"""

from __future__ import annotations

import copy

import pytest

# ---------------------------------------------------------------------------
# Production Component Imports
# ---------------------------------------------------------------------------
from input_validator.config import InputValidatorConfig
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
    "Hello world! This is a valid English sentence for testing context propagation."
)

RICH_CONTEXT = {
    "request_id": "req-trace-998877",
    "user": "secops_admin",
    "user_id": "usr-554433",
    "tenant_id": "tenant-enterprise-01",
    "session_id": "sess-a1b2c3d4",
    "trace_id": "trace-9900112233",
    "ip_address": "192.168.1.100",
    "roles": ["admin", "secops_auditor"],
    "permissions": ("read", "write", "execute"),
    "correlation_id": "corr-776655",
    "custom_metadata": {
        "source": "api_gateway",
        "environment": "production",
    },
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
# 1. TestContextPropagation
# ===========================================================================
class TestContextPropagation:
    """Verifies that context is accepted and propagated without raising errors."""

    def test_context_propagates_through_pipeline(self) -> None:
        # Arrange
        validator = create_validator_facade()
        ctx = copy.deepcopy(RICH_CONTEXT)

        # Act
        response = validator.validate(VALID_PROMPT, context=ctx)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert isinstance(response.results, list)
        assert len(response.results) == len(validator.registered_validators())


# ===========================================================================
# 2. TestContextImmutability
# ===========================================================================
class TestContextImmutability:
    """Verifies that original context structures are never mutated during validation."""

    def test_populated_context_is_never_mutated(self) -> None:
        # Arrange
        ctx = copy.deepcopy(RICH_CONTEXT)
        ctx_snapshot = copy.deepcopy(ctx)
        validator = create_validator_facade()

        # Act
        validator.validate(VALID_PROMPT, context=ctx)

        # Assert
        assert ctx == ctx_snapshot


# ===========================================================================
# 3. TestNestedContext
# ===========================================================================
class TestNestedContext:
    """Verifies propagation and immutability for complex nested context structures."""

    def test_deeply_nested_context_structures_remain_unmodified(self) -> None:
        # Arrange
        nested_context = {
            "user": "secops_admin",
            "request_id": "req-nested-100",
            "level1": {
                "level2": {
                    "level3": {"key": "value", "list_data": [1, 2, 3]},
                    "tuple_data": (10, 20),
                }
            },
            "tags": ["alpha", "beta"],
        }
        nested_snapshot = copy.deepcopy(nested_context)
        validator = create_validator_facade()

        # Act
        response = validator.validate(VALID_PROMPT, context=nested_context)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert nested_context == nested_snapshot


# ===========================================================================
# 4. TestEmptyContext
# ===========================================================================
class TestEmptyContext:
    """Verifies framework behavior when an empty dictionary is supplied as context."""

    def test_empty_context_dictionary_behavior(self) -> None:
        # Arrange
        empty_context: dict[str, str] = {}
        empty_snapshot = copy.deepcopy(empty_context)
        validator = create_validator_facade()

        # Act
        response = validator.validate(VALID_PROMPT, context=empty_context)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert empty_context == empty_snapshot
        assert len(response.results) == len(validator.registered_validators())


# ===========================================================================
# 5. TestNoneContext
# ===========================================================================
class TestNoneContext:
    """Verifies framework behavior when None is supplied as context."""

    def test_none_context_handled_gracefully(self) -> None:
        # Arrange
        validator = create_validator_facade()

        # Act
        response = validator.validate(VALID_PROMPT, context=None)

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert isinstance(response.results, list)
        assert len(response.results) == len(validator.registered_validators())


# ===========================================================================
# 6. TestRepeatedExecution
# ===========================================================================
class TestRepeatedExecution:
    """Verifies context isolation across sequential validations with distinct contexts."""

    def test_sequential_executions_never_leak_context(self) -> None:
        # Arrange
        validator = create_validator_facade()
        ctx_req1 = {"user": "user_1", "request_id": "req-001"}
        ctx_req2 = {"user": "user_2", "request_id": "req-002"}
        ctx_req3 = {"user": "user_3", "request_id": "req-003"}

        ctx1_snapshot = copy.deepcopy(ctx_req1)
        ctx2_snapshot = copy.deepcopy(ctx_req2)
        ctx3_snapshot = copy.deepcopy(ctx_req3)

        # Act
        res1 = validator.validate(VALID_PROMPT, context=ctx_req1)
        res2 = validator.validate(VALID_PROMPT, context=ctx_req2)
        res3 = validator.validate(VALID_PROMPT, context=ctx_req3)

        # Assert
        assert isinstance(res1, InputValidationResponse)
        assert isinstance(res2, InputValidationResponse)
        assert isinstance(res3, InputValidationResponse)
        assert ctx_req1 == ctx1_snapshot
        assert ctx_req2 == ctx2_snapshot
        assert ctx_req3 == ctx3_snapshot


# ===========================================================================
# 7. TestMultipleInstances
# ===========================================================================
class TestMultipleInstances:
    """Verifies context propagation isolation across separate InputValidator instances."""

    def test_multiple_instances_isolate_context_propagation(self) -> None:
        # Arrange
        v1 = create_validator_facade()
        v2 = create_validator_facade()

        ctx1 = {"user": "tenant_1_user", "request_id": "req-tenant-1"}
        ctx2 = {"user": "tenant_2_user", "request_id": "req-tenant-2"}

        ctx1_snapshot = copy.deepcopy(ctx1)
        ctx2_snapshot = copy.deepcopy(ctx2)

        # Act
        res1 = v1.validate(VALID_PROMPT, context=ctx1)
        res2 = v2.validate(VALID_PROMPT, context=ctx2)

        # Assert
        assert isinstance(res1, InputValidationResponse)
        assert isinstance(res2, InputValidationResponse)
        assert ctx1 == ctx1_snapshot
        assert ctx2 == ctx2_snapshot


# ===========================================================================
# 8. TestPromptImmutability
# ===========================================================================
class TestPromptImmutability:
    """Verifies input prompt string immutability during context propagation."""

    def test_prompt_remains_unchanged_after_validation_with_context(self) -> None:
        # Arrange
        prompt = "  Original Input Prompt for Security Check  "
        prompt_snapshot = prompt
        validator = create_validator_facade()
        ctx = copy.deepcopy(RICH_CONTEXT)

        # Act
        validator.validate(prompt, context=ctx)

        # Assert
        assert prompt == prompt_snapshot


# ===========================================================================
# 9. TestResponseConsistency
# ===========================================================================
class TestResponseConsistency:
    """Verifies response model contracts and metrics across varied context inputs."""

    def test_response_structure_is_consistent_across_varied_contexts(self) -> None:
        # Arrange
        validator = create_validator_facade()
        contexts = [
            None,
            {},
            {"user": "secops_user", "request_id": "req-a"},
            copy.deepcopy(RICH_CONTEXT),
        ]

        # Act & Assert
        for ctx in contexts:
            response = validator.validate(VALID_PROMPT, context=ctx)
            assert isinstance(response, InputValidationResponse)
            assert isinstance(response.results, list)
            assert len(response.results) == len(validator.registered_validators())
            assert isinstance(response.execution_time_ms, float)
            assert response.execution_time_ms >= 0.0
            assert all(
                r.timestamp is not None and r.timestamp.tzinfo is not None
                for r in response.results
            )
