"""
Sprint 6 Input Validator Framework integration verification script.
"""

import sys
import json
from pathlib import Path

# Add the project root to python path to resolve imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from input_validator.input_validator import InputValidator
from input_validator.config import InputValidatorConfig, LengthConfig, SchemaConfig, LanguageConfig, PipelineConfig
from input_validator.validators.empty import EmptyValidator
from input_validator.validators.length import LengthValidator
from input_validator.validators.schema import SchemaValidator
from input_validator.validators.language import LanguageValidator


def test_sprint6_framework() -> None:
    print("--- Starting Input Validator Framework Verification ---")
    
    # 1. Initialize custom configurations
    config = InputValidatorConfig(
        pipeline=PipelineConfig(fail_fast=True),
        length=LengthConfig(minimum_length=5, maximum_length=150),
        language=LanguageConfig(supported_languages=["en", "hi"], allow_unknown_languages=False),
        schema=SchemaConfig(
            enable_schema_validation=True,
            required_fields={"user_id": str, "prompt": str},
            allow_extra_fields=False,
            parse_json=True
        )
    )
    
    # 2. Inject concrete validators
    empty_val = EmptyValidator(config=None)
    length_val = LengthValidator(config=config.length)
    schema_val = SchemaValidator(config=config.schema)
    lang_val = LanguageValidator(config=config.language)
    
    validator = InputValidator(config=config, validators=[empty_val, length_val, schema_val, lang_val])
    
    # 3. Output Framework diagnostics
    print("Health Status:", json.dumps(validator.health(), indent=2))
    print("Framework Version:", validator.version)
    
    # Test Case 1: Empty prompt (Should fail on EmptyValidator)
    prompt_1 = "   "
    res_1 = validator.validate(prompt_1)
    print(f"\nTest 1 (Empty prompt): is_valid={res_1.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_1.metadata, indent=2))
    for r in res_1.results:
        print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}, metadata={r.metadata}")
        
    # Test Case 2: Too short prompt (Should fail on LengthValidator)
    prompt_2 = "abc"
    res_2 = validator.validate(prompt_2)
    print(f"\nTest 2 (Too short prompt): is_valid={res_2.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_2.metadata, indent=2))
    for r in res_2.results:
        print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}")
        
    # Test Case 3: Invalid Schema (JSON Parsing Failure)
    prompt_3 = "Not a JSON object"
    res_3 = validator.validate(prompt_3)
    print(f"\nTest 3 (JSON parsing failure): is_valid={res_3.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_3.metadata, indent=2))
    for r in res_3.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}")

    # Test Case 4: Missing field in Schema
    prompt_4 = '{"prompt": "Hello there"}'
    res_4 = validator.validate(prompt_4)
    print(f"\nTest 4 (Missing schema field): is_valid={res_4.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_4.metadata, indent=2))
    for r in res_4.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}")

    # Test Case 5: Incorrect field type in Schema
    prompt_5 = '{"user_id": 12345, "prompt": "Hello there"}'
    res_5 = validator.validate(prompt_5)
    print(f"\nTest 5 (Incorrect field type): is_valid={res_5.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_5.metadata, indent=2))
    for r in res_5.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}")

    # Test Case 6: Extra fields in Schema (Not allowed)
    prompt_6 = '{"user_id": "usr_99", "prompt": "Hello there", "extra": "forbidden"}'
    res_6 = validator.validate(prompt_6)
    print(f"\nTest 6 (Extra fields): is_valid={res_6.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_6.metadata, indent=2))
    for r in res_6.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}")

    # Test Case 7: Unsupported Language (Spanish)
    prompt_7 = '{"user_id": "usr_1", "prompt": "el perro corre rapido por el parque"}'
    res_7 = validator.validate(prompt_7)
    print(f"\nTest 7 (Unsupported language): is_valid={res_7.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_7.metadata, indent=2))
    for r in res_7.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}, metadata={r.metadata}")

    # Test Case 8: Valid inputs matching all requirements
    prompt_8 = '{"user_id": "usr_1", "prompt": "The quick brown fox jumps over the lazy dog"}'
    res_8 = validator.validate(prompt_8)
    print(f"\nTest 8 (All pass check): is_valid={res_8.is_valid}")
    print("Telemetry Metadata:", json.dumps(res_8.metadata, indent=2))
    for r in res_8.results:
         print(f"  - {r.validator_name}: is_valid={r.is_valid}, error_message={r.error_message}, metadata={r.metadata}")

    print("\n--- Verification completed successfully ---")


if __name__ == "__main__":
    test_sprint6_framework()
