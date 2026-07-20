# config.py
"""Configuration for the Input Validator module.

Defines which validator classes are active in the validation pipeline.
Modify ``VALIDATOR_CLASSES`` to add or remove validators.
"""

# Import validator classes
from .validators.empty import EmptyValidator
from .validators.length import LengthValidator
from .validators.encoding import EncodingValidator
from .validators.format import FormatValidator
from .validators.schema import SchemaValidator
from .validators.language import LanguageValidator
from .validators.context_rules import ContextRulesValidator
from .validators.file_validator import FileValidator
from .validators.completeness import CompletenessValidator

# List of validator classes to be executed in order
VALIDATOR_CLASSES = [
    EmptyValidator,
    LengthValidator,
    EncodingValidator,
    FormatValidator,
    SchemaValidator,
    LanguageValidator,
    ContextRulesValidator,
    FileValidator,
    CompletenessValidator,
]
