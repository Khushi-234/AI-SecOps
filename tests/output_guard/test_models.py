"""
Unit tests for Output Guard DTOs and models.
"""

from datetime import datetime, timezone
import pytest

from output_guard.enums import OutputAction, SanitizationType
from output_guard.models import OutputSanitizationResult, SanitizationResult


def test_sanitization_result_initialization():
    result = SanitizationResult(
        sanitizer_name="SecretSanitizer",
        sanitization_type=SanitizationType.SECRET,
        is_modified=True,
        original_output="key=AKIA1234567890ABCDEF",
        sanitized_output="key=[REDACTED_SECRET]",
        changes=[{"secret_type": "aws_access_key", "count": 1}],
        detected_issues=["Detected secret (aws_access_key)"],
        execution_time_ms=1.5,
    )

    assert result.sanitizer_name == "SecretSanitizer"
    assert result.sanitization_type == "SECRET"
    assert result.is_modified is True
    assert result.modified is True
    assert len(result.changes) == 1
    assert len(result.detected_issues) == 1
    assert result.execution_time_ms == 1.5

    data = result.to_dict()
    assert data["sanitizer_name"] == "SecretSanitizer"
    assert data["sanitization_type"] == "SECRET"
    assert data["is_modified"] is True


def test_output_sanitization_result_initialization():
    result = OutputSanitizationResult(
        original_output="Contact user@example.com",
        sanitized_output="Contact [REDACTED_PII]",
        modified=True,
        applied_sanitizers=["PiiSanitizer"],
        detected_issues=["Detected PII (email)"],
        action_taken=OutputAction.SANITIZE,
        execution_time_ms=3.2,
    )

    assert result.original_output == "Contact user@example.com"
    assert result.sanitized_output == "Contact [REDACTED_PII]"
    assert result.modified is True
    assert result.applied_sanitizers == ["PiiSanitizer"]
    assert result.action_taken == "SANITIZE"

    data = result.to_dict()
    assert data["modified"] is True
    assert data["action_taken"] == "SANITIZE"
    assert "timestamp" in data
