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

    def get_summary_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Computes aggregate security metrics from PostgreSQL audit data.
        Ensures distinct request_id counting without double-counting multi-event requests.
        """
        conditions = []
        params: List[Any] = []

        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time.astimezone(timezone.utc))
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time.astimezone(timezone.utc))

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            WITH request_summary AS (
                SELECT 
                    request_id,
                    MAX(CASE WHEN status IN ('BLOCKED', 'FAIL_SECURE', 'FAIL_SECURE_BLOCKED') OR action = 'BLOCK' THEN 1 ELSE 0 END) AS is_blocked,
                    MAX(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) AS is_critical_high
                FROM audit_events
                {where_clause}
                GROUP BY request_id
            )
            SELECT
                COUNT(*) AS total_requests,
                COALESCE(SUM(is_blocked), 0) AS blocked_requests,
                COALESCE(SUM(CASE WHEN is_blocked = 0 THEN 1 ELSE 0 END), 0) AS allowed_requests,
                (SELECT COUNT(*) FROM audit_events {where_clause}) AS total_events,
                COALESCE(SUM(is_critical_high), 0) AS critical_high_events
            FROM request_summary;
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params + params if where_clause else params))
                row = cursor.fetchone()
                cursor.close()

                if not row:
                    return {
                        "total_requests": 0,
                        "blocked_requests": 0,
                        "allowed_requests": 0,
                        "total_events": 0,
                        "critical_high_events": 0,
                    }

                tot_req, blk_req, alw_req, tot_evt, crit_evt = row
                return {
                    "total_requests": int(tot_req or 0),
                    "blocked_requests": int(blk_req or 0),
                    "allowed_requests": int(alw_req or 0),
                    "total_events": int(tot_evt or 0),
                    "critical_high_events": int(crit_evt or 0),
                }
        except Exception as exc:
            logger.error(f"Failed to calculate summary stats: {exc}")
            raise RepositoryError(
                f"Failed to compute audit summary stats: {exc}",
                original_exception=exc,
            ) from exc

    def get_recent_requests(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        component: Optional[str] = None,
        request_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves aggregated request summaries ordered by timestamp descending.
        """
        conditions = []
        params: List[Any] = []

        if status:
            if status.upper() == "BLOCKED":
                conditions.append("(status IN ('BLOCKED', 'FAIL_SECURE', 'FAIL_SECURE_BLOCKED') OR action = 'BLOCK')")
            elif status.upper() in ("ALLOWED", "SUCCESS"):
                conditions.append("status IN ('SUCCESS', 'ALLOWED') AND action != 'BLOCK'")
            else:
                conditions.append("status = %s")
                params.append(status)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if component:
            conditions.append("component = %s")
            params.append(component)
        if request_id:
            conditions.append("request_id ILIKE %s")
            params.append(f"%{request_id}%")
        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time.astimezone(timezone.utc))
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time.astimezone(timezone.utc))

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT 
                request_id,
                MAX(trace_id) AS trace_id,
                MAX(timestamp) AS last_timestamp,
                MIN(timestamp) AS start_timestamp,
                CASE 
                    WHEN MAX(CASE WHEN status IN ('BLOCKED', 'FAIL_SECURE', 'FAIL_SECURE_BLOCKED') OR action = 'BLOCK' THEN 1 ELSE 0 END) = 1 THEN 'BLOCKED'
                    ELSE 'ALLOWED'
                END AS status,
                MAX(severity) AS severity,
                MAX(action) AS action,
                COUNT(*) AS total_events,
                STRING_AGG(DISTINCT component, ', ') AS components_involved,
                COALESCE(MAX(CASE WHEN metadata->>'composite_score' IS NOT NULL THEN (metadata->>'composite_score')::float WHEN metadata->>'risk_score' IS NOT NULL THEN (metadata->>'risk_score')::float ELSE 0.0 END), 0.0) AS risk_score,
                MAX(CASE WHEN metadata->>'blocked_by' IS NOT NULL THEN metadata->>'blocked_by' WHEN status IN ('BLOCKED', 'FAIL_SECURE', 'FAIL_SECURE_BLOCKED') OR action = 'BLOCK' THEN component ELSE NULL END) AS blocked_by
            FROM audit_events
            {where_clause}
            GROUP BY request_id
            ORDER BY MAX(timestamp) DESC
            LIMIT %s OFFSET %s;
        """
        params.extend([limit, offset])

        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params))
                rows = cursor.fetchall()
                cursor.close()
                results = []
                for row in rows:
                    req_id = row[0]
                    trc_id = row[1]
                    last_ts = row[2]
                    start_ts = row[3]
                    stat = row[4]
                    sev = row[5]
                    act = row[6]
                    evt_cnt = row[7]
                    comps = row[8]
                    r_score = row[9] if len(row) > 9 else 0.0
                    blk_by = row[10] if len(row) > 10 else None
                    results.append(
                        {
                            "request_id": req_id,
                            "trace_id": trc_id,
                            "timestamp": last_ts.isoformat() if hasattr(last_ts, "isoformat") else str(last_ts),
                            "start_timestamp": start_ts.isoformat() if hasattr(start_ts, "isoformat") else str(start_ts),
                            "status": stat,
                            "severity": sev,
                            "action": act,
                            "event_count": evt_cnt,
                            "components": comps,
                            "risk_score": float(r_score or 0.0),
                            "blocked_by": blk_by,
                        }
                    )
                return results
        except Exception as exc:
            logger.error(f"Failed to fetch recent requests: {exc}")
            raise RepositoryError(
                f"Failed to query recent request records: {exc}",
                original_exception=exc,
            ) from exc

    def get_analytics_breakdown(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves breakdown counts for status, component, severity, action, and event_type.
        """
        conditions = []
        params: List[Any] = []

        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time.astimezone(timezone.utc))
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time.astimezone(timezone.utc))

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        def fetch_distribution(column_name: str) -> Dict[str, int]:
            query_sql = f"""
                SELECT {column_name}, COUNT(*)
                FROM audit_events
                {where_clause}
                GROUP BY {column_name};
            """
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query_sql, tuple(params))
                rows = cursor.fetchall()
                cursor.close()
                return {str(k if k is not None else "UNKNOWN"): int(v) for k, v in rows}

        try:
            return {
                "status": fetch_distribution("status"),
                "severity": fetch_distribution("severity"),
                "component": fetch_distribution("component"),
                "action": fetch_distribution("action"),
                "event_type": fetch_distribution("event_type"),
            }
        except Exception as exc:
            logger.error(f"Failed to calculate analytics breakdown: {exc}")
            raise RepositoryError(
                f"Failed to query analytics breakdown: {exc}",
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
