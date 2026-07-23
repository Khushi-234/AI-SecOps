# test_file_validator.py
"""Unit tests for FileValidator in input_validator.validators."""

import pytest
from pathlib import Path
from types import SimpleNamespace
from input_validator.validators.file_validator import FileValidator
from input_validator.models import ValidationResult


class TestFileValidator:
    """Test suite for FileValidator security checks (path traversal, extensions, restricted paths)."""

    def test_properties(self) -> None:
        validator = FileValidator(config=None)
        assert validator.validator_name == "FileValidator"
        assert validator.priority == 55

    def test_valid_existing_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "valid_doc.json"
        test_file.write_text('{"key": "value"}')

        validator = FileValidator(config=None)
        prompt = "Analyze attached file"
        context = {"file_path": str(test_file)}

        result = validator.validate(prompt, context)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.metadata["problematic_keys"] == []

    def test_path_traversal_detection(self) -> None:
        validator = FileValidator(config=None)
        prompt = "Read secret"
        context = {"file_path": "../../../etc/passwd"}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "path traversal sequence ('..') detected" in result.error_message

    def test_unapproved_extension(self, tmp_path: Path) -> None:
        test_file = tmp_path / "script.exe"
        test_file.write_text("binary content")

        validator = FileValidator(config=None)
        prompt = "Execute script"
        context = {"attachment": str(test_file)}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "unapproved file extension '.exe'" in result.error_message

    def test_restricted_system_directory(self) -> None:
        validator = FileValidator(config=None)
        prompt = "Inspect system log"
        context = {"document": "/etc/shadow"}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert any(
            msg in result.error_message
            for msg in [
                "access to restricted system location denied",
                "file lacks read permission",
                "file does not exist",
            ]
        )

    def test_file_does_not_exist(self, tmp_path: Path) -> None:
        non_existent = tmp_path / "missing.txt"

        validator = FileValidator(config=None)
        prompt = "Read text"
        context = {"file_path": str(non_existent)}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "file does not exist" in result.error_message

    def test_custom_allowed_extensions_in_config(self, tmp_path: Path) -> None:
        test_file = tmp_path / "data.custom"
        test_file.write_text("content")

        config = SimpleNamespace(allowed_extensions={"custom"})
        validator = FileValidator(config=config)
        prompt = "Read custom format"
        context = {"file": str(test_file)}

        result = validator.validate(prompt, context)
        assert result.is_valid is True
