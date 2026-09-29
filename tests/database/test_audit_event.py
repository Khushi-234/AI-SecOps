"""
Unit tests for AuditEvent Model & Secret Scrubbing (Sprint 12 Phase 5, 6, 12, 13).
"""

import pytest
from datetime import datetime, timezone
from database.models.audit_event import (
    AuditEvent,
    AuditEventCategory,
    EventAction,
    EventSeverity,
    EventStatus,
    sanitize_payload,
)


def test_audit_event_creation_and_defaults():
    evt = AuditEvent(
        request_id="req_12345",
        component="InputValidator",
        event_type=AuditEventCategory.INPUT_VALIDATION,
        message="Valid prompt submitted.",
    )

    assert evt.event_id.startswith("evt_")
    assert evt.request_id == "req_12345"
    assert evt.trace_id == "req_12345"  # Defaults to request_id
    assert evt.component == "InputValidator"
    assert evt.event_type == "INPUT_VALIDATION"
    assert evt.severity == "INFO"
    assert evt.action == "ALLOW"
    assert evt.status == "SUCCESS"
    assert evt.timestamp.tzinfo == timezone.utc


def test_audit_event_empty_request_id_raises():
    with pytest.raises(ValueError):
        AuditEvent(
            request_id="",
            component="InputValidator",
            event_type="INPUT_VALIDATION",
            message="Test",
        )


def test_audit_event_empty_component_raises():
    with pytest.raises(ValueError):
        AuditEvent(
            request_id="req_123",
            component="",
            event_type="INPUT_VALIDATION",
            message="Test",
        )


def test_secret_scrubbing_metadata():
    raw_metadata = {
        "user_id": "user_42",
        "api_key": "gsk_1234567890abcdef1234567890",
        "password": "super_secret_password",
        "nested": {
            "bearer_token": "Bearer secret_jwt_token_here",
            "safe_field": "clean_value",
        },
    }

    evt = AuditEvent(
        request_id="req_999",
        component="PromptFirewall",
        event_type=AuditEventCategory.PROMPT_FIREWALL,
        message="Checking payload with api_key in message gsk_1234567890abcdef1234567890",
        metadata=raw_metadata,
    )

    meta = evt.metadata
    assert meta["user_id"] == "user_42"
    assert meta["api_key"] == "[REDACTED]"
    assert meta["password"] == "[REDACTED]"
    assert meta["nested"]["safe_field"] == "clean_value"
    assert meta["nested"]["bearer_token"] == "[REDACTED]"
    assert "gsk_" not in evt.message


def test_sanitize_payload_utility():
    dirty = {
        "GROQ_API_KEY": "gsk_secretkey123456789",
        "authToken": "abc.xyz.123",
        "items": ["safe", "gsk_1234567890abcdef12345"],
    }
    clean = sanitize_payload(dirty)
    assert clean["GROQ_API_KEY"] == "[REDACTED]"
    assert clean["authToken"] == "[REDACTED]"
    assert clean["items"][0] == "safe"
    assert clean["items"][1] == "[REDACTED]"


def test_audit_event_to_dict():
    evt = AuditEvent(
        request_id="req_111",
        component="RiskEngine",
        event_type=AuditEventCategory.RISK_ASSESSMENT,
        severity=EventSeverity.WARNING,
        action=EventAction.WARN,
        status=EventStatus.SUCCESS,
        message="Risk score threshold exceeded.",
        metadata={"risk_score": 0.75},
    )
    d = evt.to_dict()
    assert d["request_id"] == "req_111"
    assert d["event_type"] == "RISK_ASSESSMENT"
    assert d["severity"] == "WARNING"
    assert d["action"] == "WARN"
    assert d["metadata"]["risk_score"] == 0.75
