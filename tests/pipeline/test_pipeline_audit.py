"""
Integration and Unit tests for AISecOpsPipeline Audit Logging & Database Integration (Sprint 12 Phase 9, 10, 12).
"""

from unittest.mock import MagicMock
import pytest

from database.audit.audit_logger import DatabaseAuditLogger
from database.exceptions import RepositoryError
from database.models.audit_event import AuditEvent
from pipeline.config import PipelineConfig
from pipeline.exceptions import FailSecurePipelineError
from pipeline.pipeline import AISecOpsPipeline
from pipeline.request import PipelineRequest
from pipeline.response import PipelineStatus


def test_pipeline_audit_event_generation_success():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = lambda evt: evt

    audit_logger = DatabaseAuditLogger(repository=mock_repo)
    config = PipelineConfig(enable_audit_logging=True)
    pipeline = AISecOpsPipeline(config=config, audit_logger=audit_logger)

    req = PipelineRequest(user_prompt="Explain quantum computing in simple terms.")
    resp = pipeline.execute(req)

    assert resp.status == PipelineStatus.SUCCESS
    assert resp.success is True

    # Check saved audit events
    assert mock_repo.save.call_count >= 8
    events = [call[0][0] for call in mock_repo.save.call_args_list]

    components = [e.component for e in events]
    assert "AISecOpsPipeline" in components
    assert "InputValidator" in components
    assert "PromptBuilder" in components
    assert "PromptFirewall" in components
    assert "RiskEngine" in components
    assert "PolicyEngine" in components
    assert "PromptHardener" in components
    assert "LLMProvider" in components
    assert "OutputGuard" in components

    # Traceability check
    for evt in events:
        assert evt.request_id == req.request_id
        assert evt.trace_id == req.request_id


def test_pipeline_audit_early_exit_blocked():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = lambda evt: evt

    # Mock an input validator that blocks input
    mock_validator = MagicMock()
    mock_val_resp = MagicMock()
    mock_val_resp.is_valid = False
    mock_result = MagicMock()
    mock_result.is_valid = False
    mock_result.error_message = "Malformed prompt length error."
    mock_val_resp.results = [mock_result]
    mock_validator.validate.return_value = mock_val_resp

    audit_logger = DatabaseAuditLogger(repository=mock_repo)
    pipeline = AISecOpsPipeline(
        input_validator=mock_validator,
        audit_logger=audit_logger,
    )

    req = PipelineRequest(user_prompt="invalid prompt")
    resp = pipeline.execute(req)

    assert resp.status == PipelineStatus.BLOCKED
    assert resp.blocked is True
    assert resp.blocked_by == "InputValidator"

    events = [call[0][0] for call in mock_repo.save.call_args_list]
    block_events = [e for e in events if e.status == "BLOCKED"]
    assert len(block_events) > 0
    assert block_events[0].component in ("InputValidator", "AISecOpsPipeline")


def test_pipeline_db_failure_does_not_bypass_security():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = RepositoryError("PostgreSQL connection timeout")

    # DB logger fails, but fail_secure_on_db_error is False (default non-crashing audit mode)
    audit_logger = DatabaseAuditLogger(repository=mock_repo, fail_secure_on_db_error=False)
    pipeline = AISecOpsPipeline(audit_logger=audit_logger)

    req = PipelineRequest(user_prompt="Hello safe prompt")
    resp = pipeline.execute(req)

    # Security checks still ran, pipeline completed safely
    assert resp.status == PipelineStatus.SUCCESS
    assert resp.success is True


def test_pipeline_db_failure_triggers_fail_secure_when_configured():
    mock_repo = MagicMock()
    mock_repo.save.side_effect = RepositoryError("PostgreSQL cluster unavailable")

    audit_logger = DatabaseAuditLogger(repository=mock_repo, fail_secure_on_db_error=True)
    config = PipelineConfig(fail_secure_on_db_error=True)
    pipeline = AISecOpsPipeline(config=config, audit_logger=audit_logger)

    req = PipelineRequest(user_prompt="Hello safe prompt")
    resp = pipeline.execute(req)

    # Fail-secure exit is triggered, request is blocked safely!
    assert resp.status == PipelineStatus.FAIL_SECURE_BLOCKED
    assert resp.blocked is True
    assert resp.success is False
