"""
Unit tests for AuditRepository (Sprint 12 Phase 7 & 12).
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest
from database.connection import PostgresConnectionManager
from database.exceptions import RepositoryError
from database.models.audit_event import AuditEvent, AuditEventCategory
from database.repositories.audit_repository import AuditRepository


def test_repository_save_and_retrieve_by_id():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    repo = AuditRepository(connection_manager=mgr)

    evt = AuditEvent(
        event_id="evt_001",
        request_id="req_001",
        trace_id="trc_001",
        component="InputValidator",
        event_type=AuditEventCategory.INPUT_VALIDATION,
        message="Valid prompt",
    )

    saved = repo.save(evt)
    assert saved.event_id == "evt_001"
    mock_cursor.execute.assert_called_once()
    mock_conn.commit.assert_called_once()

    # Setup fetch return
    now_utc = datetime.now(timezone.utc)
    mock_cursor.fetchone.return_value = (
        "evt_001",
        "req_001",
        "trc_001",
        now_utc,
        "InputValidator",
        "INPUT_VALIDATION",
        "INFO",
        "ALLOW",
        "SUCCESS",
        "Valid prompt",
        '{"key": "val"}',
    )

    fetched = repo.get_by_id("evt_001")
    assert fetched is not None
    assert fetched.event_id == "evt_001"
    assert fetched.request_id == "req_001"
    assert fetched.metadata == {"key": "val"}


def test_repository_get_by_request_id():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    now_utc = datetime.now(timezone.utc)
    mock_cursor.fetchall.return_value = [
        ("evt_1", "req_ABC", "req_ABC", now_utc, "InputValidator", "INPUT_VALIDATION", "INFO", "ALLOW", "SUCCESS", "Msg 1", "{}"),
        ("evt_2", "req_ABC", "req_ABC", now_utc, "PromptFirewall", "PROMPT_FIREWALL", "INFO", "ALLOW", "SUCCESS", "Msg 2", "{}"),
    ]

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    repo = AuditRepository(connection_manager=mgr)

    events = repo.get_by_request_id("req_ABC")
    assert len(events) == 2
    assert events[0].event_id == "evt_1"
    assert events[1].event_id == "evt_2"


def test_repository_get_by_trace_id():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    now_utc = datetime.now(timezone.utc)
    mock_cursor.fetchall.return_value = [
        ("evt_1", "req_XYZ", "trace_XYZ", now_utc, "RiskEngine", "RISK_ASSESSMENT", "INFO", "ALLOW", "SUCCESS", "Msg", "{}"),
    ]

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    repo = AuditRepository(connection_manager=mgr)

    events = repo.get_by_trace_id("trace_XYZ")
    assert len(events) == 1
    assert events[0].trace_id == "trace_XYZ"


def test_repository_save_exception_raises_repository_error():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.execute.side_effect = Exception("DB Disk Full")

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    repo = AuditRepository(connection_manager=mgr)

    evt = AuditEvent(
        request_id="req_err",
        component="RiskEngine",
        event_type="RISK_ASSESSMENT",
        message="Test",
    )

    with pytest.raises(RepositoryError):
        repo.save(evt)
