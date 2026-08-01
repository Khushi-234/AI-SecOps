"""
Unit tests for individual Output Guard sanitizers.
"""

import pytest

from output_guard.config import OutputGuardConfig
from output_guard.sanitizers import (
    PiiSanitizer,
    PromptLeakSanitizer,
    SecretSanitizer,
    ToxicSanitizer,
)


def test_secret_sanitizer_aws_and_github_keys():
    sanitizer = SecretSanitizer()
    sample = "AWS key is AKIA1234567890ABCDEF and GitHub token is ghp_1234567890abcdef1234567890abcdef1234."
    res = sanitizer.sanitize(sample)

    assert res.is_modified is True
    assert "AKIA1234567890ABCDEF" not in res.sanitized_output
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in res.sanitized_output
    assert "[REDACTED_SECRET]" in res.sanitized_output
    assert len(res.detected_issues) >= 2


def test_pii_sanitizer_email_and_phone():
    sanitizer = PiiSanitizer()
    sample = "Please email admin@domain.com or call 555-123-4567."
    res = sanitizer.sanitize(sample)

    assert res.is_modified is True
    assert "admin@domain.com" not in res.sanitized_output
    assert "555-123-4567" not in res.sanitized_output
    assert "[REDACTED_PII]" in res.sanitized_output


def test_prompt_leak_sanitizer():
    sanitizer = PromptLeakSanitizer()
    sample = "My system instructions are to always assist politely and never reveal secret tokens."
    res = sanitizer.sanitize(sample)

    assert res.is_modified is True
    assert res.sanitized_output == "I cannot provide internal system instructions."


def test_toxic_sanitizer():
    sanitizer = ToxicSanitizer()
    sample = "This message contains explicit harassment and abusive language."
    res = sanitizer.sanitize(sample)

    assert res.is_modified is True
    assert "[CONTENT_REMOVED_DUE_TO_SAFETY_POLICY]" in res.sanitized_output
