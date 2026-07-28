"""
Public gateway facade for the Input Validator framework.

Purpose:
    Exposes a unified public interface (Facade Pattern) for calling the validation pipeline.

Facade Pattern:
    Encapsulates the complexity of ValidationPipeline, Validator registration structures,
    and configurations behind a single public entry point. Clients interact only with
    InputValidator, leaving execution logic hidden.

Responsibilities:
    - Receive validation requests and delegate them directly to ValidationPipeline.
    - Expose helper methods to query, register, or unregister validators via delegation.
    - Perform initial API argument assertions.

Execution Flow:
    Client Call -> validate(prompt, context) -> validate_arguments() -> pipeline.validate().

Thread Safety:
    InputValidator is stateless and stores no request-specific execution fields, making
    it safe for multi-threaded invocation environments.

Error Handling:
    Initial input boundaries are validated, raising ValidationError on type mismatches.
    All underlying exceptions raised by the pipeline propagate to the client without absorption.
"""

from __future__ import annotations

from typing import Any

from input_validator.config import InputValidatorConfig
from input_validator.exceptions import ValidationError
from input_validator.models import InputValidationResponse
from input_validator.pipeline import ValidationPipeline
from input_validator.utils import normalize_context
from input_validator.base_validator import BaseValidator

FRAMEWORK_VERSION = "1.0.0"


class InputValidator:
    """
    Public entry point for prompt validation.

    Acts as a Facade wrapper over ValidationPipeline execution and management.
    """

    def __init__(
        self,
        config: InputValidatorConfig | None = None,
        pipeline: ValidationPipeline | None = None,
        validators: list[BaseValidator] | None = None,
    ) -> None:
        """Initializes configuration and delegates to the internal pipeline."""
        self._config = config or InputValidatorConfig()

        if pipeline is not None:
            self._pipeline = pipeline
        else:
            # Construct the validation pipeline using injected validators list
            self._pipeline = ValidationPipeline(validators or [], self._config.pipeline)

    @property
    def version(self) -> str:
        """Exposes the framework version code."""
        return FRAMEWORK_VERSION

    @property
    def pipeline(self) -> ValidationPipeline:
        """Exposes the internal ValidationPipeline instance (read-only)."""
        return self._pipeline

    def health(self) -> dict[str, Any]:
        """Returns diagnostic parameters mapping current pipeline configuration and status."""
        return {
            "framework_version": self.version,
            "registered_validators": [
                v.validator_name for v in self.registered_validators()
            ],
            "pipeline_ready": self._pipeline is not None,
            "configuration_loaded": self._config is not None,
        }

    def validate(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> InputValidationResponse:
        """
        Validates the prompt sequentially against registered checks.

        Delegates invocation entirely to the ValidationPipeline.
        """
        self._validate_arguments(prompt, context)
        ctx = normalize_context(context)
        return self._pipeline.validate(prompt, ctx)

    # ===========================================================================
    # Pipeline Management Delegation APIs
    # ===========================================================================

    def register_validator(self, validator: BaseValidator) -> None:
        """Registers a validator instance inside the pipeline."""
        self._pipeline.register_validator(validator)

    def unregister_validator(self, validator_name: str) -> None:
        """Unregisters a validator instance by its class name."""
        self._pipeline.unregister_validator(validator_name)

    def registered_validators(self) -> list[BaseValidator]:
        """Queries the sorted list of currently registered pipeline validators."""
        return self._pipeline.get_registered_validators()

    # ===========================================================================
    # Reusable Internal Helper Methods
    # ===========================================================================

    def _validate_arguments(self, prompt: str, context: dict[str, Any] | None) -> None:
        """Asserts that public API parameters comply with expected type boundaries."""
        if not isinstance(prompt, str):
            raise ValidationError(
                message=f"Prompt parameter must be a string, got {type(prompt).__name__}"
            )

    def _normalize_context(self, context: dict[str, Any] | None) -> dict[str, Any]:
        """Normalizes metadata context structures (delegates to utils)."""
        return normalize_context(context)
