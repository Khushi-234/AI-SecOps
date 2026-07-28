"""
Schema structure validation checker.

Purpose:
    Validates the structural integrity and parameter types of structured input payloads.

Responsibilities:
    - Deserialize JSON input strings or return dictionaries directly.
    - Check that all configured required fields exist.
    - Validate that each required field's value matches its expected Python type.
    - Reject unexpected fields if allow_extra_fields is disabled.

Future Extensions:
    Holds TODO placeholders for integrating:
        - JSON Schema Draft 2020-12
        - Pydantic model validation
        - OpenAPI request validation
        - MCP request schema validation

Thread Safety:
    This class is stateless and thread-safe for parallel evaluations.
"""

from __future__ import annotations

import json
from typing import Any

from input_validator.base_validator import BaseValidator


class SchemaValidator(BaseValidator):
    """Enforces structure and type validation on prompt payloads."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "SchemaValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority (lower executes first)."""
        return 30

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Performs schema structural checks on the prompt payload."""
        schema_config = self.config

        # TODO: Implement JSON Schema Draft 2020-12 validation support in Sprint 6.2.
        # TODO: Implement Pydantic model validation support in Sprint 6.2.
        # TODO: Implement OpenAPI request validation support in Sprint 6.2.
        # TODO: Implement MCP request schema validation support in Sprint 6.2.

        if not schema_config.enable_schema_validation:
            return True, None, {"schema_enabled": False, "validation_passed": True}

        payload: dict[str, Any] | None = None
        if schema_config.parse_json:
            parsed_payload, parse_err = self._deserialize_payload(prompt)
            if parse_err:
                meta = self._build_metadata([], [], [], 0, False)
                return False, f"Input validation failed: {parse_err}", meta
            payload = parsed_payload
        else:
            # Retrieve payload from context or fallback to prompt deserialization
            payload = context.get("payload")
            if payload is None:
                if prompt.strip().startswith("{"):
                    parsed_payload, _ = self._deserialize_payload(prompt)
                    payload = parsed_payload

        if not isinstance(payload, dict):
            meta = self._build_metadata([], [], [], 0, False)
            return (
                False,
                "Input validation failed: expected structured payload dictionary.",
                meta,
            )

        required_fields = schema_config.required_fields

        # Initialize validation tracking variables
        missing: list[str] = []
        invalid: list[tuple[str, str, str]] = []
        extra: list[str] = []
        is_valid = True
        error_message = None
        validated_count = 0

        # 1. Verify required fields exist
        missing = self._validate_required_fields(payload, required_fields)
        if missing:
            is_valid = False
            error_message = (
                f"Input validation failed: required field '{missing[0]}' is missing."
            )
            validated_count = len(required_fields) - len(missing)
        else:
            # All required fields are present, validate their types
            invalid = self._validate_field_types(payload, required_fields)
            validated_count = len(required_fields)

            if invalid:
                is_valid = False
                field_name, expected, actual = invalid[0]
                error_message = (
                    f"Input validation failed: field '{field_name}' must be of type '{expected}', "
                    f"received '{actual}'."
                )
            elif not schema_config.allow_extra_fields:
                # 3. Handle unexpected extra fields
                extra = self._validate_extra_fields(payload, required_fields)
                if extra:
                    is_valid = False
                    error_message = f"Input validation failed: unexpected extra field '{extra[0]}' is not allowed."

        # Compile telemetry metadata exactly once
        meta = self._build_metadata(missing, invalid, extra, validated_count, is_valid)
        return is_valid, error_message, meta

    # ===========================================================================
    # Reusable Protected Helper Methods
    # ===========================================================================

    def _deserialize_payload(
        self, prompt: Any
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Attempts deserialization on dict or string payloads."""
        if isinstance(prompt, dict):
            return prompt, None
        if not isinstance(prompt, str):
            return None, f"Expected string or dict payload, got {type(prompt).__name__}"
        try:
            parsed = json.loads(prompt)
            if not isinstance(parsed, dict):
                return None, "JSON payload must be a dictionary/structured object"
            return parsed, None
        except json.JSONDecodeError as e:
            return None, f"JSON parse error: {e}"

    def _validate_required_fields(
        self, payload: dict[str, Any], required_fields: dict[str, Any]
    ) -> list[str]:
        """Returns required field names missing from payload."""
        return [field for field in required_fields if field not in payload]

    def _validate_field_types(
        self, payload: dict[str, Any], required_fields: dict[str, Any]
    ) -> list[tuple[str, str, str]]:
        """Returns fields violating type rules as list of tuples (field, expected_type, actual_type)."""
        invalid_types = []
        for field, expected_type in required_fields.items():
            if field in payload:
                val = payload[field]
                if not isinstance(val, expected_type):
                    invalid_types.append(
                        (field, expected_type.__name__, type(val).__name__)
                    )
        return invalid_types

    def _validate_extra_fields(
        self, payload: dict[str, Any], required_fields: dict[str, Any]
    ) -> list[str]:
        """Returns keys present in payload but absent from required_fields."""
        return [key for key in payload if key not in required_fields]

    def _build_metadata(
        self,
        missing: list[str],
        invalid: list[tuple[str, str, str]],
        extra: list[str],
        validated_count: int,
        validation_passed: bool,
    ) -> dict[str, Any]:
        """Compiles telemetry metadata mapping schema validation details."""
        required_keys = list(self.config.required_fields.keys())
        invalid_formatted = [
            f"{field}: expected {expected}, got {actual}"
            for field, expected, actual in invalid
        ]
        return {
            "schema_enabled": self.config.enable_schema_validation,
            "required_fields": required_keys,
            "missing_fields": missing,
            "invalid_fields": invalid_formatted,
            "extra_fields": extra,
            "validated_field_count": validated_count,
            "validation_passed": validation_passed,
        }
