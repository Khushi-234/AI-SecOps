# base_validator.py
"""Base class for all validators using the Template Method pattern.

Each validator implements the ``_validate`` method that receives a
:class:`~input_validator.context.ValidationContext` and returns a
:class:`~input_validator.models.ValidationResult`.
"""

from abc import ABC, abstractmethod
from .simple_validator import SimpleValidator
from ..models import ValidationResult
from ..context import ValidationContext


class BaseValidator(ABC, SimpleValidator):
    """Abstract validator defining the validation flow.

    The ``validate`` method handles common setup/error handling and then
    delegates to ``_validate`` which concrete subclasses must implement.
    """

    @abstractmethod
    def _validate(self, context: ValidationContext) -> ValidationResult:
        """Core validation logic for the concrete validator.

        Must return a :class:`ValidationResult`.
        """
        raise NotImplementedError

    def validate(self, context: ValidationContext) -> ValidationResult:
        """Template method that runs the validator.

        It catches unexpected exceptions and turns them into a failed
        :class:`ValidationResult` with the exception message.
        """
        try:
            return self._validate(context)
        except Exception as exc:  # pragma: no cover – defensive
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=str(exc),
                details={"exception": repr(exc)},
            )
