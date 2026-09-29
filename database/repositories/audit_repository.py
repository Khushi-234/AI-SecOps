"""
Audit Repository for PostgreSQL Audit Event persistence and querying.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.connection import PostgresConnectionManager
from database.exceptions import RepositoryError
from database.models.audit_event import AuditEvent

logger = logging.getLogger("ai_secops_repository")


class AuditRepository:
    """
    Data Access Object (DAO) / Repository for persisting and retrieving AuditEvent records.

    Contains persistence and SQL query logic ONLY. Does not perform threat detection,
    risk scoring, or policy decisions.
    """

    def __init__(self, connection_manager: PostgresConnectionManager) -> None:
        self.db = connection_manager

    def save(self, event: AuditEvent) -> AuditEvent:
        """
        Persists a single AuditEvent record into the PostgreSQL database.

        Args:
            event: AuditEvent instance to persist.

        Returns:
            The saved AuditEvent instance.
        """
        sql = """
            INSERT INTO audit_events (
                event_id, request_id, trace_id, timestamp, component,
                event_type, severity, action, status, message, metadata
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """
        meta_json = json.dumps(event.metadata)
        ts_utc = event.timestamp.astimezone(timezone.utc)

        try:
            with self.db.transaction() as cursor:
                cursor.execute(
                    sql,
                    (
                        event.event_id,
                        event.request_id,
                        event.trace_id,
                        ts_utc,
                        event.component,
                        event.event_type,
                        event.severity,
                        event.action,
                        event.status,
                        event.message,
                        meta_json,
                    ),
                )
            return event
        except Exception as exc:
            logger.error(f"Failed to save AuditEvent {event.event_id}: {exc}")
            raise RepositoryError(
                f"Failed to persist AuditEvent record: {exc}",
                original_exception=exc,
            ) from exc

    def get_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """
        Retrieves a single AuditEvent by its event_id.

        Args:
            event_id: Unique audit event string identifier.

        Returns:
            AuditEvent if found, None otherwise.
        """
        sql = """
            SELECT event_id, request_id, trace_id, timestamp, component,
                   event_type, severity, action, status, message, metadata
            FROM audit_events
            WHERE event_id = %s;
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (event_id,))
                row = cursor.fetchone()
                cursor.close()
                if not row:
                    return None
                return self._row_to_audit_event(row)
        except Exception as exc:
            logger.error(f"Failed to retrieve AuditEvent by id '{event_id}': {exc}")
            raise RepositoryError(
                f"Failed to fetch AuditEvent record by ID: {exc}",
                original_exception=exc,
            ) from exc

    def get_by_request_id(self, request_id: str) -> List[AuditEvent]:
        """
        Retrieves all AuditEvents associated with a request_id, ordered chronologically.

        Args:
            request_id: Correlation request identifier string.

        Returns:
            List of matching AuditEvent records.
        """
        sql = """
            SELECT event_id, request_id, trace_id, timestamp, component,
                   event_type, severity, action, status, message, metadata
            FROM audit_events
            WHERE request_id = %s
            ORDER BY timestamp ASC;
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (request_id,))
                rows = cursor.fetchall()
                cursor.close()
                return [self._row_to_audit_event(row) for row in rows]
        except Exception as exc:
            logger.error(f"Failed to retrieve AuditEvents by request_id '{request_id}': {exc}")
            raise RepositoryError(
                f"Failed to fetch AuditEvent records by request_id: {exc}",
                original_exception=exc,
            ) from exc

    def get_by_trace_id(self, trace_id: str) -> List[AuditEvent]:
        """
        Retrieves all AuditEvents associated with a trace_id, ordered chronologically.

        Args:
            trace_id: Distributed trace identifier string.

        Returns:
            List of matching AuditEvent records.
        """
        sql = """
            SELECT event_id, request_id, trace_id, timestamp, component,
                   event_type, severity, action, status, message, metadata
            FROM audit_events
            WHERE trace_id = %s
            ORDER BY timestamp ASC;
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, (trace_id,))
                rows = cursor.fetchall()
                cursor.close()
                return [self._row_to_audit_event(row) for row in rows]
        except Exception as exc:
            logger.error(f"Failed to retrieve AuditEvents by trace_id '{trace_id}': {exc}")
            raise RepositoryError(
                f"Failed to fetch AuditEvent records by trace_id: {exc}",
                original_exception=exc,
            ) from exc

    def query_events(
        self,
        component: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Filters and retrieves AuditEvents based on component, event_type, severity, or timestamp range.
        """
        conditions = []
        params: List[Any] = []

        if component:
            conditions.append("component = %s")
            params.append(component)
        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time.astimezone(timezone.utc))
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time.astimezone(timezone.utc))

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"""
            SELECT event_id, request_id, trace_id, timestamp, component,
                   event_type, severity, action, status, message, metadata
            FROM audit_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT %s;
        """
        params.append(limit)

        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params))
                rows = cursor.fetchall()
                cursor.close()
                return [self._row_to_audit_event(row) for row in rows]
        except Exception as exc:
            logger.error(f"Failed to query AuditEvents: {exc}")
            raise RepositoryError(
                f"Failed to query AuditEvent records: {exc}",
                original_exception=exc,
            ) from exc

    def _row_to_audit_event(self, row: tuple) -> AuditEvent:
        """Helper method converting DB query tuple to AuditEvent object."""
        (
            event_id,
            request_id,
            trace_id,
            timestamp,
            component,
            event_type,
            severity,
            action,
            status,
            message,
            metadata_raw,
        ) = row

        if isinstance(metadata_raw, str):
            metadata = json.loads(metadata_raw)
        elif isinstance(metadata_raw, dict):
            metadata = metadata_raw
        else:
            metadata = {}

        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp)
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            dt = datetime.now(timezone.utc)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return AuditEvent(
            event_id=str(event_id),
            request_id=str(request_id),
            trace_id=str(trace_id),
            timestamp=dt,
            component=str(component),
            event_type=str(event_type),
            severity=str(severity),
            action=str(action),
            status=str(status),
            message=str(message),
            metadata=metadata,
        )
