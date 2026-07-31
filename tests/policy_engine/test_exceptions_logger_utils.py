"""
Unit tests for exceptions, logger, and utils modules in policy_engine.
"""

from __future__ import annotations

import logging
import re
import pytest

from policy_engine.exceptions import (
    InvalidPolicyInputError,
    PolicyConfigurationError,
    PolicyEngineError,
    PolicyExecutionError,
    SanitizationError,
)
from policy_engine.logger import get_policy_logger, log_policy_decision
from policy_engine.models import SanitizationEdit
from policy_engine.utils import apply_sanitization_edits, sanitize_pattern


# =============================================================================
# Exception Hierarchy Tests
# =============================================================================


def test_policy_engine_error_base():
    cause_exc = ValueError("Root cause")
    err = PolicyEngineError(
        message="Test error",
        field="risk_score",
        value=-5,
        details={"extra": "meta"},
        cause=cause_exc,
    )

    assert err.message == "Test error"
    assert err.details == {"extra": "meta", "field": "risk_score", "value": -5}
    assert err.timestamp is not None
    assert err.__cause__ is cause_exc

    d = err.to_dict()
    assert d["error_type"] == "PolicyEngineError"
    assert d["message"] == "Test error"
    assert d["details"] == {"extra": "meta", "field": "risk_score", "value": -5}
    assert "timestamp" in d


def test_derived_exceptions():
    assert issubclass(InvalidPolicyInputError, PolicyEngineError)
    assert issubclass(PolicyConfigurationError, PolicyEngineError)
    assert issubclass(SanitizationError, PolicyEngineError)
    assert issubclass(PolicyExecutionError, PolicyEngineError)

    inv_err = InvalidPolicyInputError("Invalid payload")
    assert inv_err.message == "Invalid payload"


# =============================================================================
# Logger Tests
# =============================================================================


def test_get_policy_logger():
    log_inst = get_policy_logger()
    assert isinstance(log_inst, logging.Logger)
    assert log_inst.name == "policy_engine"


def test_log_policy_decision(caplog):
    log_inst = get_policy_logger()
    log_inst.setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="policy_engine")

    # BLOCK -> warning
    log_policy_decision("req-1", "BLOCK", "High risk score", 95.0, "RISK_SCORE_RULE")
    assert any("[PolicyEngine Audit] Request: req-1 | Action: BLOCK" in record.message for record in caplog.records)

    # WARN / SANITIZE -> info
    log_policy_decision("req-2", "WARN", "Elevated risk score", 50.0, "RISK_SCORE_RULE")
    assert any("[PolicyEngine Audit] Request: req-2 | Action: WARN" in record.message for record in caplog.records)

    log_policy_decision("req-3", "SANITIZE", "PII detected", 75.0, "PII_RULE")
    assert any("[PolicyEngine Audit] Request: req-3 | Action: SANITIZE" in record.message for record in caplog.records)

    # ALLOW -> debug
    log_policy_decision("req-4", "ALLOW", "Clean prompt", 10.0, "ALLOW_RULE")
    assert any("[PolicyEngine Audit] Request: req-4 | Action: ALLOW" in record.message for record in caplog.records)


# =============================================================================
# Utils Tests
# =============================================================================


def test_apply_sanitization_edits_empty():
    assert apply_sanitization_edits("Hello World", []) == "Hello World"


def test_apply_sanitization_edits_multiple():
    prompt = "Contact alice@example.com or bob@example.com"
    edit1 = SanitizationEdit(
        edit_id="e1",
        sanitization_type="PII_REDACTION",
        original_text="alice@example.com",
        replacement_text="[REDACTED]",
        start_char=8,
        end_char=25,
    )
    edit2 = SanitizationEdit(
        edit_id="e2",
        sanitization_type="PII_REDACTION",
        original_text="bob@example.com",
        replacement_text="[REDACTED]",
        start_char=29,
        end_char=44,
    )

    result = apply_sanitization_edits(prompt, [edit1, edit2])
    assert result == "Contact [REDACTED] or [REDACTED]"


def test_apply_sanitization_edits_out_of_bounds():
    prompt = "Short"
    invalid_edit = SanitizationEdit(
        edit_id="e_out",
        sanitization_type="TEST",
        original_text="None",
        replacement_text="XXX",
        start_char=10,
        end_char=20,
    )
    # Should safely skip edits out of string bounds
    assert apply_sanitization_edits(prompt, [invalid_edit]) == "Short"


def test_sanitize_pattern_string():
    prompt = "Call 123-456-7890 now"
    sanitized, edits = sanitize_pattern(prompt, r"\d{3}-\d{3}-\d{4}", "[PHONE]", "PII_REDACTION")

    assert sanitized == "Call [PHONE] now"
    assert len(edits) == 1
    assert edits[0].original_text == "123-456-7890"
    assert edits[0].replacement_text == "[PHONE]"


def test_sanitize_pattern_compiled_regex():
    prompt = "User secret: key-1234567890"
    pattern = re.compile(r"key-\d+", re.IGNORECASE)
    sanitized, edits = sanitize_pattern(prompt, pattern, "[REDACTED]", "SECRET_MASKING")

    assert sanitized == "User secret: [REDACTED]"
    assert len(edits) == 1
    assert edits[0].original_text == "key-1234567890"
