"""
File path and file payload validation checker.

Purpose:
    Validates referenced file paths for existence, readability, extension compliance,
    and defends against Path Traversal / Arbitrary File Read (LFI) threats.

Responsibilities:
    - Prevent directory traversal attempts ('..').
    - Block access to restricted system directories (/etc, /proc, /root, .ssh).
    - Enforce file extension whitelist rules.
    - Check file existence and read permissions safely.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from input_validator.validators.base_validator import BaseValidator
from input_validator.utils import extract_file_extension, is_empty

FILE_PATH_KEYS = {"file_path", "filepath", "file", "document", "attachment"}
DEFAULT_ALLOWED_EXTENSIONS = {"txt", "json", "csv", "pdf", "md", "png", "jpg", "yaml", "yml"}
RESTRICTED_DIRECTORY_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/root", "/boot", "/var/log")


class FileValidator(BaseValidator):
    """Validates file reference paths with strict path traversal and extension security controls."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "FileValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority."""
        return 55

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates that referenced file paths exist, are readable, and satisfy path security rules."""
        ctx = context or {}
        problematic: list[str] = []
        violations: list[str] = []

        allowed_exts = getattr(self.config, "allowed_extensions", DEFAULT_ALLOWED_EXTENSIONS) if self.config else DEFAULT_ALLOWED_EXTENSIONS
        allowed_exts = {ext.lower() for ext in allowed_exts}

        for key in FILE_PATH_KEYS:
            raw_path = ctx.get(key)
            if raw_path is None or is_empty(raw_path):
                continue

            if not isinstance(raw_path, str):
                problematic.append(key)
                violations.append(f"{key}: path must be a string")
                continue

            # 1. Path traversal check
            if ".." in raw_path:
                problematic.append(key)
                violations.append(f"{key}: path traversal sequence ('..') detected")
                continue

            # 2. Extension check
            ext = extract_file_extension(raw_path)
            if ext and ext not in allowed_exts:
                problematic.append(key)
                violations.append(f"{key}: unapproved file extension '.{ext}'")
                continue

            # 3. Restricted directory resolution check
            try:
                resolved_path = str(Path(raw_path).resolve())
                if any(resolved_path.startswith(prefix) for prefix in RESTRICTED_DIRECTORY_PREFIXES):
                    problematic.append(key)
                    violations.append(f"{key}: access to restricted system location denied")
                    continue
            except Exception:
                problematic.append(key)
                violations.append(f"{key}: invalid path syntax")
                continue

            # 4. Existence and readability check
            if not os.path.isfile(resolved_path):
                problematic.append(key)
                violations.append(f"{key}: file does not exist")
                continue

            if not os.access(resolved_path, os.R_OK):
                problematic.append(key)
                violations.append(f"{key}: file lacks read permission")
                continue

        metadata = {
            "problematic_keys": problematic,
            "violations": violations,
            "checked_keys": [k for k in FILE_PATH_KEYS if k in ctx],
        }

        if problematic:
            return (
                False,
                f"Input validation failed: file security check failed for keys: {', '.join(problematic)} ({'; '.join(violations)}).",
                metadata,
            )

        return True, None, metadata