"""
Enterprise-grade unit test suite for SchemaValidator component.

Validates constructor configuration injection, schema disabled mode, JSON string deserialization,
direct dictionary payloads, required field presence, field type correctness, unexpected extra field rules,
custom configurations, telemetry metadata structure, boundary/edge cases, statelessness, and context/payload immutability.
"""

import copy
from datetime import datetime, timedelta, timezone
import json
from typing import Any

import pytest

from input_validator.config import SchemaConfig
from input_validator.models import ValidationResult
from input_validator.validators.schema import SchemaValidator


# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for SchemaValidator construction and public properties."""

    def test_constructor_initialization(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"user_id": int},
            allow_extra_fields=False,
            parse_json=True,
        )

        # Act
        validator = SchemaValidator(config=config)

        # Assert
        assert validator.config is config
        assert validator.config.enable_schema_validation is True
        assert validator.config.required_fields == {"user_id": int}
        assert validator.config.allow_extra_fields is False
        assert validator.config.parse_json is True

    def test_validator_name_property(self) -> None:
        # Arrange & Act
        validator = SchemaValidator(config=SchemaConfig())

        # Assert
        assert validator.validator_name == "SchemaValidator"

    def test_priority_property(self) -> None:
        # Arrange & Act
        validator = SchemaValidator(config=SchemaConfig())

        # Assert
        assert validator.priority == 30


# ===========================================================================
# 2. TestSchemaDisabled
# ===========================================================================


class TestSchemaDisabled:
    """Test suite when enable_schema_validation is set to False."""

    def test_validation_succeeds_when_schema_disabled(self) -> None:
        # Arrange
        config = SchemaConfig(enable_schema_validation=False)
        validator = SchemaValidator(config=config)

        # Act
        result = validator.validate("arbitrary string prompt")

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata == {
            "schema_enabled": False,
            "validation_passed": True,
        }


# ===========================================================================
# 3. TestJsonParsing
# ===========================================================================


class TestJsonParsing:
    """Test suite for JSON string deserialization when parse_json is True."""

    def test_valid_json_object_parsed_and_accepted(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"query": str},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        json_prompt = json.dumps({"query": "select * from database"})

        # Act
        result = validator.validate(json_prompt)

        # Assert
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["validation_passed"] is True

    def test_invalid_json_string_rejected(self) -> None:
        # Arrange
        config = SchemaConfig(enable_schema_validation=True, parse_json=True)
        validator = SchemaValidator(config=config)
        invalid_json = "{invalid_json_syntax: missing_quotes}"

        # Act
        result = validator.validate(invalid_json)

        # Assert
        assert result.is_valid is False
        assert "Input validation failed: JSON parse error" in (
            result.error_message or ""
        )
        assert result.metadata["validation_passed"] is False

    @pytest.mark.parametrize(
        "non_dict_json_prompt, description",
        [
            ("[1, 2, 3]", "JSON array"),
            ('"just a string"', "JSON string primitive"),
            ("12345", "JSON number"),
            ("true", "JSON boolean"),
            ("null", "JSON null"),
        ],
    )
    def test_non_dictionary_json_payloads_rejected(
        self, non_dict_json_prompt: str, description: str
    ) -> None:
        # Arrange
        config = SchemaConfig(enable_schema_validation=True, parse_json=True)
        validator = SchemaValidator(config=config)

        # Act
        result = validator.validate(non_dict_json_prompt)

        # Assert
        assert result.is_valid is False
        assert (
            "JSON payload must be a dictionary/structured object"
            in (result.error_message or "")
        )
        assert result.metadata["validation_passed"] is False


# ===========================================================================
# 4. TestDictInput
# ===========================================================================


class TestDictInput:
    """Test suite for direct dictionary payloads passed via context or auto-deserialization."""

    def test_already_parsed_dictionary_in_context_accepted(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"action": str, "level": int},
            parse_json=False,
        )
        validator = SchemaValidator(config=config)
        context = {"payload": {"action": "scan", "level": 3}}

        # Act
        result = validator.validate("ignored_prompt", context=context)

        # Assert
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["validated_field_count"] == 2

    def test_prompt_starting_with_brace_deserialized_when_context_payload_missing(
        self,
    ) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"status": str},
            parse_json=False,
        )
        validator = SchemaValidator(config=config)
        json_prompt = '{"status": "ok"}'

        # Act
        result = validator.validate(json_prompt, context={})

        # Assert
        assert result.is_valid is True
        assert result.error_message is None

    def test_non_dictionary_payload_rejected(self) -> None:
        # Arrange
        config = SchemaConfig(enable_schema_validation=True, parse_json=False)
        validator = SchemaValidator(config=config)
        context = {"payload": "not_a_dictionary"}

        # Act
        result = validator.validate("plain text prompt", context=context)

        # Assert
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: expected structured payload dictionary."
        )


# ===========================================================================
# 5. TestRequiredFields
# ===========================================================================


class TestRequiredFields:
    """Test suite verifying required field existence in payload."""

    def test_all_required_fields_present_succeeds(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"name": str, "age": int, "tags": list},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        prompt = json.dumps({"name": "Bob", "age": 30, "tags": ["admin"]})

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["missing_fields"] == []
        assert result.metadata["validated_field_count"] == 3

    def test_single_required_field_missing_fails(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"name": str, "email": str},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        prompt = json.dumps({"name": "Alice"})  # missing email

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: required field 'email' is missing."
        )
        assert result.metadata["missing_fields"] == ["email"]
        assert result.metadata["validated_field_count"] == 1

    def test_multiple_required_fields_missing_fails(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"id": int, "role": str, "active": bool},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        prompt = json.dumps({})  # missing id, role, active

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is False
        assert "is missing" in (result.error_message or "")
        assert set(result.metadata["missing_fields"]) == {"id", "role", "active"}
        assert result.metadata["validated_field_count"] == 0

    def test_empty_payload_with_required_fields_fails(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"token": str},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)

        # Act
        result = validator.validate("{}")

        # Assert
        assert result.is_valid is False
        assert result.metadata["missing_fields"] == ["token"]


# ===========================================================================
# 6. TestTypeValidation
# ===========================================================================


class TestTypeValidation:
    """Test suite verifying expected Python type matching for required fields."""

    @pytest.mark.parametrize(
        "field_name, expected_type, valid_val, invalid_val, actual_type_name",
        [
            ("int_field", int, 100, "100", "str"),
            ("float_field", float, 99.9, "99.9", "str"),
            ("bool_field", bool, True, "true", "str"),
            ("list_field", list, [1, 2], "1,2", "str"),
            ("dict_field", dict, {"k": "v"}, ["k", "v"], "list"),
            ("str_field", str, "text", 12345, "int"),
        ],
    )
    def test_field_type_validation_rules(
        self,
        field_name: str,
        expected_type: type,
        valid_val: Any,
        invalid_val: Any,
        actual_type_name: str,
    ) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={field_name: expected_type},
            parse_json=False,
        )
        validator = SchemaValidator(config=config)

        # Act - Valid type
        valid_result = validator.validate(
            "dummy", context={"payload": {field_name: valid_val}}
        )

        # Act - Invalid type
        invalid_result = validator.validate(
            "dummy", context={"payload": {field_name: invalid_val}}
        )

        # Assert
        assert valid_result.is_valid is True

        assert invalid_result.is_valid is False
        assert (
            f"field '{field_name}' must be of type '{expected_type.__name__}', received '{actual_type_name}'."
            in (invalid_result.error_message or "")
        )
        assert len(invalid_result.metadata["invalid_fields"]) == 1

    def test_none_value_for_non_nullable_type_fails(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"username": str},
            parse_json=False,
        )
        validator = SchemaValidator(config=config)

        # Act
        result = validator.validate("dummy", context={"payload": {"username": None}})

        # Assert
        assert result.is_valid is False
        assert "field 'username' must be of type 'str', received 'NoneType'." in (
            result.error_message or ""
        )


# ===========================================================================
# 7. TestExtraFields
# ===========================================================================


class TestExtraFields:
    """Test suite for allow_extra_fields configuration mode."""

    def test_extra_fields_allowed_when_enabled(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"id": int},
            allow_extra_fields=True,
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        prompt = json.dumps({"id": 1, "extra_1": "a", "extra_2": 2})

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["extra_fields"] == []

    def test_extra_fields_rejected_when_disabled(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"id": int},
            allow_extra_fields=False,
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        prompt = json.dumps({"id": 1, "unauthorized_field": "val"})

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: unexpected extra field 'unauthorized_field' is not allowed."
        )
        assert result.metadata["extra_fields"] == ["unauthorized_field"]


# ===========================================================================
# 8. TestConfiguration
# ===========================================================================


class TestConfiguration:
    """Test suite verifying validator adherence to distinct SchemaConfig objects."""

    def test_multiple_schema_config_modes(self) -> None:
        # Arrange
        config_strict = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"key": str},
            allow_extra_fields=False,
            parse_json=True,
        )
        config_permissive = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"key": str},
            allow_extra_fields=True,
            parse_json=True,
        )

        validator_strict = SchemaValidator(config=config_strict)
        validator_permissive = SchemaValidator(config=config_permissive)

        payload_str = json.dumps({"key": "val", "bonus": True})

        # Act
        result_strict = validator_strict.validate(payload_str)
        result_permissive = validator_permissive.validate(payload_str)

        # Assert
        assert result_strict.is_valid is False
        assert result_permissive.is_valid is True


# ===========================================================================
# 9. TestMetadata
# ===========================================================================


class TestMetadata:
    """Test suite verifying telemetry metadata key-value contract."""

    def test_metadata_structure_on_success(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"a": str, "b": int},
            allow_extra_fields=True,
            parse_json=False,
        )
        validator = SchemaValidator(config=config)
        context = {"payload": {"a": "hello", "b": 42}, "request_id": "req-schema-1"}

        # Act
        result = validator.validate("dummy", context=context)

        # Assert
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata == {
            "schema_enabled": True,
            "required_fields": ["a", "b"],
            "missing_fields": [],
            "invalid_fields": [],
            "extra_fields": [],
            "validated_field_count": 2,
            "validation_passed": True,
            "request_id": "req-schema-1",
        }

    def test_metadata_structure_on_type_failure(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"count": int},
            parse_json=False,
        )
        validator = SchemaValidator(config=config)
        context = {"payload": {"count": "not_an_int"}}

        # Act
        result = validator.validate("dummy", context=context)

        # Assert
        assert result.metadata["validation_passed"] is False
        assert result.metadata["invalid_fields"] == ["count: expected int, got str"]
        assert result.metadata["validated_field_count"] == 1


# ===========================================================================
# 10. TestValidationResult
# ===========================================================================


class TestValidationResult:
    """Test suite verifying returned ValidationResult attributes, timing, and timezone-aware UTC timestamps."""

    def test_validation_result_contract(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"query": str},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        context = {"request_id": "req-schema-contract"}

        # Act
        result = validator.validate('{"query": "test"}', context=context)

        # Assert
        assert result.validator_name == "SchemaValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata["request_id"] == "req-schema-contract"


# ===========================================================================
# 11. TestEdgeCases
# ===========================================================================


class TestEdgeCases:
    """Test suite for boundary edge cases, unicode keys/values, and deeply nested dictionaries."""

    def test_empty_dictionary_payload_edge_case(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={},
            allow_extra_fields=False,
            parse_json=False,
        )
        validator = SchemaValidator(config=config)

        # Act
        result = validator.validate("dummy", context={"payload": {}})

        # Assert
        assert result.is_valid is True
        assert result.metadata["validated_field_count"] == 0

    def test_unicode_and_emoji_field_names_and_values(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"漢字_field": str, "emoji_🚀": int},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        payload_str = json.dumps({"漢字_field": "🌟 Unicode Text", "emoji_🚀": 100})

        # Act
        result = validator.validate(payload_str)

        # Assert
        assert result.is_valid is True

    def test_deeply_nested_dictionary_payload(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"meta": dict},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        nested_payload = {"meta": {"level1": {"level2": {"level3": "deep_val"}}}}

        # Act
        result = validator.validate(json.dumps(nested_payload))

        # Assert
        assert result.is_valid is True

    def test_large_dictionary_payload(self) -> None:
        # Arrange
        required_fields = {f"field_{i}": int for i in range(100)}
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields=required_fields,
            allow_extra_fields=True,
            parse_json=False,
        )
        validator = SchemaValidator(config=config)
        large_payload = {f"field_{i}": i for i in range(100)}

        # Act
        result = validator.validate("dummy", context={"payload": large_payload})

        # Assert
        assert result.is_valid is True
        assert result.metadata["validated_field_count"] == 100


# ===========================================================================
# 12. TestStatelessness
# ===========================================================================


class TestStatelessness:
    """Test suite verifying stateless execution and multi-instance independence."""

    def test_stateless_repeated_execution(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"token": str},
            parse_json=True,
        )
        validator = SchemaValidator(config=config)
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            valid_res = validator.validate('{"token": "valid_token"}')
            assert valid_res.is_valid is True

            invalid_res = validator.validate('{"wrong_key": "val"}')
            assert invalid_res.is_valid is False

    def test_multiple_instances_state_independence(self) -> None:
        # Arrange
        config_a = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"user": str},
            parse_json=True,
        )
        config_b = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"admin": bool},
            parse_json=True,
        )

        validator_a = SchemaValidator(config=config_a)
        validator_b = SchemaValidator(config=config_b)

        payload_a = json.dumps({"user": "alice"})

        # Act
        res_a = validator_a.validate(payload_a)
        res_b = validator_b.validate(payload_a)

        # Assert
        assert res_a.is_valid is True
        assert res_b.is_valid is False


# ===========================================================================
# 13. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying context and payload dictionary immutability."""

    def test_context_and_payload_dictionaries_not_modified(self) -> None:
        # Arrange
        config = SchemaConfig(
            enable_schema_validation=True,
            required_fields={"id": int},
            allow_extra_fields=True,
            parse_json=False,
        )
        validator = SchemaValidator(config=config)

        original_payload = {"id": 101, "extra": "data"}
        original_context = {
            "request_id": "req-schema-immutable",
            "payload": original_payload,
        }

        context_snapshot = copy.deepcopy(original_context)
        payload_snapshot = copy.deepcopy(original_payload)

        # Act
        validator.validate("dummy prompt", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert original_payload == payload_snapshot
