# file_validator.py
"""Validator that checks file path fields for existence and readability.

If a value in the input dictionary is a string ending with a typical file
extension (e.g., ".txt", ".json", ".csv"), this validator verifies that the
path points to an existing file on the local filesystem. It does not attempt
to open the file – only a stat check for existence and read permissions.
"""

import os
from typing import List

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty

# Simple heuristic: keys that likely contain file paths.
FILE_PATH_KEYS = {"file_path", "filepath", "file", "document"}


class FileValidator(BaseValidator):
    """Ensures referenced file paths exist and are readable."""

    def _validate(self, context) -> ValidationResult:
        data = context.data
        problematic: List[str] = []
        for key in FILE_PATH_KEYS:
            path = data.get(key)
            if path is None or is_empty(path):
                continue  # Not provided – other validators handle required fields.
            if not isinstance(path, str):
                problematic.append(key)
                continue
            if not os.path.isfile(path):
                problematic.append(key)
                continue
            if not os.access(path, os.R_OK):
                problematic.append(key)
        if problematic:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"File validation failed for keys: {', '.join(problematic)}",
                details={"invalid_keys": problematic},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All referenced files exist and are readable.",
        )
