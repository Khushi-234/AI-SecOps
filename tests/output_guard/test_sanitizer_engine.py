"""
Unit tests for the main OutputGuard / OutputSanitizer redaction engine.
"""

import pytest

from output_guard import OutputGuard, OutputGuardConfig, OutputAction
from output_guard.exceptions import InvalidOutputError


def test_output_guard_clean_response():
    guard = OutputGuard()
    res = guard.sanitize("This is a safe and helpful assistant response.")

    assert res.modified is False
    assert res.sanitized_output == "This is a safe and helpful assistant response."
    assert res.action_taken == "ALLOW"
    assert len(res.applied_sanitizers) == 0


def test_output_guard_multiple_sanitizations():
    guard = OutputGuard()
    sample = (
        "Here is the user email user@company.org and AWS key AKIA9876543210FEDCBA."
    )
    res = guard.sanitize(sample)

    assert res.modified is True
    assert res.action_taken == "SANITIZE"
    assert "user@company.org" not in res.sanitized_output
    assert "AKIA9876543210FEDCBA" not in res.sanitized_output
    assert "SecretSanitizer" in res.applied_sanitizers
    assert "PiiSanitizer" in res.applied_sanitizers


def test_output_guard_raise_on_error():
    config = OutputGuardConfig(raise_on_error=True)
    guard = OutputGuard(config=config)

    with pytest.raises(InvalidOutputError):
        guard.sanitize(None)
