"""
Dashboard Service providing business logic & database interaction for the Streamlit UI.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from database.config import DatabaseConfig
from database.connection import PostgresConnectionManager
from database.exceptions import DatabaseConnectionError, RepositoryError
from database.models.audit_event import AuditEvent
from database.repositories.audit_repository import AuditRepository
from pipeline import AISecOpsPipeline, PipelineResponse

logger = logging.getLogger("ai_secops_dashboard_service")


class DashboardService:
    """
    Data service abstracting PostgreSQL database interactions for the Streamlit Dashboard.
    Ensures Streamlit components do NOT execute direct SQL queries.
    """

    def __init__(self, repository: Optional[AuditRepository] = None) -> None:
        if repository:
            self.repo = repository
        else:
            config = DatabaseConfig()
            self.db_manager = PostgresConnectionManager(config=config)
            self.repo = AuditRepository(connection_manager=self.db_manager)
        self._pipeline: Optional[AISecOpsPipeline] = None

    def get_pipeline(self) -> AISecOpsPipeline:
        """Lazy-initializes and returns the AISecOpsPipeline wired to PostgreSQL audit logger."""
        if self._pipeline is None:
            from database import DatabaseAuditLogger
            from pipeline.builder import AISecOpsPipelineBuilder
            from security.detectors import (
                DelimiterEscapeDetector,
                EncodingDetector,
                JailbreakDetector,
                PromptInjectionDetector,
                SecretExtractionDetector,
                ToolAbuseDetector,
                UnicodeDetector,
            )
            from security.normalizer import TextNormalizer
            from security.prompt_firewall import PromptFirewall

            audit_logger = DatabaseAuditLogger(repository=self.repo)
            normalizer = TextNormalizer()
            detectors = [
                PromptInjectionDetector(),
                JailbreakDetector(),
                UnicodeDetector(),
                EncodingDetector(),
                SecretExtractionDetector(),
                DelimiterEscapeDetector(),
                ToolAbuseDetector(),
            ]
            firewall = PromptFirewall(
                detectors=detectors,
                audit_logger=audit_logger,
                normalizer=normalizer,
                fail_secure=True,
            )

            self._pipeline = (
                AISecOpsPipelineBuilder()
                .with_prompt_firewall(firewall)
                .with_audit_logger(audit_logger)
                .build()
            )
        return self._pipeline

    def execute_query(
        self,
        prompt: str,
        user_id: str = "dashboard_user",
        stage_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    ) -> PipelineResponse:
        """Executes a user query against the real framework security pipeline."""
        from pipeline.request import PipelineRequest

        pipeline = self.get_pipeline()
        request = PipelineRequest(user_prompt=prompt, user_id=user_id)
        return pipeline.execute(request, stage_callback=stage_callback)


    def check_connection(self) -> Tuple[bool, str]:
        """
        Verifies whether PostgreSQL database is accessible and audit_events table exists.
        """
        try:
            with self.repo.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'audit_events'
                    );
                    """
                )
                exists = cursor.fetchone()[0]
                cursor.close()
                if not exists:
                    return False, "Table 'audit_events' missing. Please run migrations: python -m database.migrations.migrate"
                return True, "PostgreSQL connected cleanly."
        except Exception as exc:
            logger.error(f"Dashboard connection check failed: {exc}")
            return False, f"PostgreSQL Connection Error: {exc}"

    def get_kpi_metrics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Fetches top-level security KPI metrics.
        """
        try:
            return self.repo.get_summary_stats(start_time=start_time, end_time=end_time)
        except Exception as exc:
            logger.error(f"Failed to load KPI metrics: {exc}")
            return {
                "total_requests": 0,
                "blocked_requests": 0,
                "allowed_requests": 0,
                "total_events": 0,
                "critical_high_events": 0,
                "error": str(exc),
            }

    def get_requests(
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
        Fetches request summaries for monitoring table.
        """
        try:
            return self.repo.get_recent_requests(
                limit=limit,
                offset=offset,
                status=status,
                severity=severity,
                component=component,
                request_id=request_id,
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as exc:
            logger.error(f"Failed to load request summaries: {exc}")
            return []

    def get_request_details(self, request_id: str) -> List[AuditEvent]:
        """
        Fetches full chronological audit event lifecycle for a single request.
        """
        if not request_id or not request_id.strip():
            return []
        try:
            return self.repo.get_by_request_id(request_id=request_id.strip())
        except Exception as exc:
            logger.error(f"Failed to load request details for '{request_id}': {exc}")
            return []


    def get_analytics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Fetches analytics breakdowns for dashboard charts.
        """
        try:
            return self.repo.get_analytics_breakdown(start_time=start_time, end_time=end_time)
        except Exception as exc:
            logger.error(f"Failed to load analytics breakdown: {exc}")
            return {
                "status": {},
                "severity": {},
                "component": {},
                "action": {},
                "event_type": {},
            }

    def query_filtered_events(
        self,
        component: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Retrieves raw AuditEvents matching filters.
        """
        try:
            return self.repo.query_events(
                component=component,
                event_type=event_type,
                severity=severity,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
            )
        except Exception as exc:
            logger.error(f"Failed to query filtered events: {exc}")
            return []
