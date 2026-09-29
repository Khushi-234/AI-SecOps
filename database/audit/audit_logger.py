"""
DatabaseAuditLogger implementation bridging security modules/pipeline to PostgreSQL persistence.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from database.exceptions import DatabaseError, RepositoryError
from database.models.audit_event import (
    AuditEvent,
    AuditEventCategory,
    EventAction,
    EventSeverity,
    EventStatus,
)
from database.repositories.audit_repository import AuditRepository
from security.audit_logger import AuditLogger

logger = logging.getLogger("ai_secops_audit_service")


class DatabaseAuditLogger(AuditLogger):
    """
    Concrete AuditLogger implementation storing structured audit events in PostgreSQL via AuditRepository.

    Implements the security.audit_logger.AuditLogger abstract base class interface and provides
    fail-safe database error handling and secret redaction.
    """

    def __init__(
        self,
        repository: Optional[AuditRepository] = None,
        fail_secure_on_db_error: bool = False,
    ) -> None:
        self.repository = repository
        self.fail_secure_on_db_error = fail_secure_on_db_error

    def log_event(
        self, event_type: str, request_id: str, details: dict[str, Any]
    ) -> None:
        """
        Implementation of abstract AuditLogger interface.

        Args:
            event_type: Category identifier of the event.
            request_id: Core correlation identifier.
            details: Contextual payload containing findings, component name, and timings.
        """
        component = str(details.get("component", details.get("stage", "PromptFirewall")))
        message = str(details.get("message", f"Audit event: {event_type}"))
        severity = details.get("severity", EventSeverity.INFO)
        action = details.get("action", EventAction.ALLOW)
        status = details.get("status", EventStatus.SUCCESS)
        trace_id = details.get("trace_id", request_id)

        meta = {k: v for k, v in details.items() if k not in ("component", "stage", "message")}

        event = AuditEvent(
            request_id=request_id,
            trace_id=trace_id,
            component=component,
            event_type=event_type,
            severity=severity,
            action=action,
            status=status,
            message=message,
            metadata=meta,
        )

        self.record_event(event)

    def record_event(self, event: AuditEvent) -> Optional[AuditEvent]:
        """
        Persists a structured AuditEvent using the repository.

        Handles database failures safely: logs an error/warning and returns None
        if database is unavailable, or re-raises if fail_secure_on_db_error is True.
        """
        if self.repository is None:
            logger.warning(
                f"[AuditLogger] No AuditRepository configured. Event '{event.event_id}' skipped."
            )
            return None

        try:
            return self.repository.save(event)
        except (RepositoryError, DatabaseError) as db_exc:
            logger.error(
                f"[AuditLogger DB Failure] Failed to persist audit event '{event.event_id}' "
                f"for request '{event.request_id}': {db_exc}"
            )
            if self.fail_secure_on_db_error:
                raise
            return None
        except Exception as exc:
            logger.error(
                f"[AuditLogger Unexpected Failure] Could not record audit event '{event.event_id}': {exc}"
            )
            if self.fail_secure_on_db_error:
                raise
            return None

    def log_stage_event(
        self,
        component: str,
        event_type: AuditEventCategory | str,
        request_id: str,
        message: str,
        severity: EventSeverity | str = EventSeverity.INFO,
        action: EventAction | str = EventAction.ALLOW,
        status: EventStatus | str = EventStatus.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Optional[AuditEvent]:
        """
        Helper method to build and record a structured stage event.
        """
        event = AuditEvent(
            request_id=request_id,
            trace_id=trace_id or request_id,
            component=component,
            event_type=event_type,
            severity=severity,
            action=action,
            status=status,
            message=message,
            metadata=metadata or {},
        )
        return self.record_event(event)
