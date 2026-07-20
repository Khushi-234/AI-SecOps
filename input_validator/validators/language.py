# language.py
"""Validator that ensures the input specifies a supported language.

The field ``language`` is expected to be a string indicating the language of the
content (e.g., "en", "es", "fr"). This validator checks that the provided value
is within the ``ALLOWED_LANGUAGES`` whitelist.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty

ALLOWED_LANGUAGES = {"en", "es", "fr", "de", "zh", "ja"}


class LanguageValidator(BaseValidator):
    """Ensures ``language`` is present and supported."""

    def _validate(self, context) -> ValidationResult:
        data = context.data
        lang = data.get("language")
        if is_empty(lang):
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message="'language' field is missing or empty.",
                details={"field": "language"},
            )
        if not isinstance(lang, str) or lang not in ALLOWED_LANGUAGES:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Unsupported language: {lang}",
                details={"allowed": sorted(ALLOWED_LANGUAGES)},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="Language is supported.",
        )
