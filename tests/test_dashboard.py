"""
Unit tests for Sprint 13 Dashboard Service & UI Integration.
"""

from unittest.mock import MagicMock
import pytest
from dashboard.services.dashboard_service import DashboardService
from database.models.audit_event import AuditEvent


def test_dashboard_service_kpi_metrics():
    mock_repo = MagicMock()
    mock_repo.get_summary_stats.return_value = {
        "total_requests": 5,
        "blocked_requests": 1,
        "allowed_requests": 4,
        "total_events": 25,
        "critical_high_events": 1,
    }

    service = DashboardService(repository=mock_repo)
    metrics = service.get_kpi_metrics()

    assert metrics["total_requests"] == 5
    assert metrics["blocked_requests"] == 1
    assert metrics["allowed_requests"] == 4
    mock_repo.get_summary_stats.assert_called_once()


def test_dashboard_service_get_requests():
    mock_repo = MagicMock()
    mock_repo.get_recent_requests.return_value = [
        {"request_id": "req_001", "status": "BLOCKED", "severity": "CRITICAL"}
    ]

    service = DashboardService(repository=mock_repo)
    reqs = service.get_requests(limit=10)

    assert len(reqs) == 1
    assert reqs[0]["request_id"] == "req_001"
    mock_repo.get_recent_requests.assert_called_once_with(
        limit=10,
        offset=0,
        status=None,
        severity=None,
        component=None,
        request_id=None,
        start_time=None,
        end_time=None,
    )


def test_dashboard_service_request_details():
    mock_repo = MagicMock()
    evt = AuditEvent(
        event_id="evt_1",
        request_id="req_999",
        component="PromptFirewall",
        event_type="PROMPT_FIREWALL",
        message="Prompt injection detected",
        status="BLOCKED",
        action="BLOCK",
        severity="CRITICAL",
    )
    mock_repo.get_by_request_id.return_value = [evt]

    service = DashboardService(repository=mock_repo)
    details = service.get_request_details("req_999")

    assert len(details) == 1
    assert details[0].request_id == "req_999"
    assert details[0].status == "BLOCKED"


def test_dashboard_service_empty_request_id_returns_empty():
    mock_repo = MagicMock()
    service = DashboardService(repository=mock_repo)

    assert service.get_request_details("") == []
    assert service.get_request_details("   ") == []
    mock_repo.get_by_request_id.assert_not_called()
