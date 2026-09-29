"""
Unit tests for DatabaseAuditLogger & Audit Service abstraction (Sprint 12 Phase 8, 10, 12).
"""

from unittest.mock import MagicMock
import pytest
from database.audit.audit_logger import DatabaseAuditLogger
from database.exceptions import RepositoryError
from database.models.audit_event import AuditEvent, AuditEventCategory


def test_audit_logger_record_event():
    mock_repo = MagicMock()
    evt = AuditEvent(
        request_id="req_555",
        component="PromptHardener",
        event_type=AuditEventCategory.PROMPT_HARDENING,
        message="Hardening rules applied.",
    )
    mock_repo.save.return_value = evt

    logger_service = DatabaseAuditLogger(repository=mock_repo)
    result = logger_service.record_event(evt)

    assert result == evt
    mock_repo.save.assert_called_once_with(evt)


def test_audit_logger_log_event_interface():
    mock_repo = MagicMock()
    logger_service = DatabaseAuditLogger(repository=mock_repo)

    logger_service.log_event(
        event_type="PROMPT_AUDIT",
        request_id="req_777",
        details={
            "component": "PromptFirewall",
            "message": "Firewall check passed",
            "severity": "INFO",
            "action": "ALLOW",
            "status": "SUCCESS",
            "detector_findings": ["clean"],
        },
    )

    mock_repo.save.assert_called_once()
    saved_evt = mock_repo.save.call_args[0][0]
    assert saved_evt.request_id == "req_777"
    assert saved_evt.component == "PromptFirewall"
    assert saved_evt.event_type == "PROMPT_AUDIT"


def test_audit_logger_db_failure_handled_safely():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = RepositoryError("Database offline")

    # When fail_secure_on_db_error is False (default)
    logger_service = DatabaseAuditLogger(
        repository=mock_repo, fail_secure_on_db_error=False
    )
    evt = AuditEvent(
        request_id="req_fail",
        component="OutputGuard",
        event_type="OUTPUT_GUARD",
        message="Safe check",
    )

    res = logger_service.record_event(evt)
    assert res is None  # Handled safely, returns None, does not crash


def test_audit_logger_db_failure_raises_when_fail_secure():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = RepositoryError("Database offline")

    # When fail_secure_on_db_error is True
    logger_service = DatabaseAuditLogger(
        repository=mock_repo, fail_secure_on_db_error=True
    )
    evt = AuditEvent(
        request_id="req_fail",
        component="OutputGuard",
        event_type="OUTPUT_GUARD",
        message="Safe check",
    )

    with pytest.raises(RepositoryError):
        logger_service.record_event(evt)
