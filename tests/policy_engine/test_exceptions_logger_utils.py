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
)
from policy_engine.logger import get_policy_logger, log_policy_decision
from policy_engine.utils import normalize_threat_name


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


def test_normalize_threat_name():
    assert normalize_threat_name(" Credential_Leak ") == "credential_leak"
    assert normalize_threat_name("JAILBREAK") == "jailbreak"

