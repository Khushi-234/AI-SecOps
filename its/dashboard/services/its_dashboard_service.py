"""
ITSDashboardService — Central Dashboard Backend Coordinator.

Coordinates domain services (TrafficService, IncidentService, RouteService),
AI-SecOps security pipeline adapter (AISecOpsAdapter), and optional PostgreSQL
audit logging without blocking dashboard operations if the database is offline.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.connection import PostgresConnectionManager
from database.repositories.audit_repository import AuditRepository
from its.integration.aisecops_adapter import AISecOpsAdapter
from its.models.its_models import (
    Incident,
    ITSResponse,
    Road,
    TrafficCondition,
)
from its.services.incident_service import IncidentService
from its.services.route_service import RouteService
from its.services.traffic_service import TrafficService
from pipeline import PipelineResponse

logger = logging.getLogger("its_dashboard_service")


class ITSDashboardService:
    """
    Unified facade service powering the Intelligent Transportation System SOC Dashboard.

    Provides high-level domain telemetry queries and processes operator inquiries
    strictly through the AISecOpsAdapter and frozen 8-stage security pipeline.
    Audit persistence to PostgreSQL is non-blocking: falls back to in-memory session
    telemetry if PostgreSQL is unavailable.
    """

    def __init__(
        self,
        adapter: Optional[AISecOpsAdapter] = None,
        traffic_service: Optional[TrafficService] = None,
        incident_service: Optional[IncidentService] = None,
        route_service: Optional[RouteService] = None,
        audit_repo: Optional[AuditRepository] = None,
    ) -> None:
        """
        Initializes domain services, adapter, and optional PostgreSQL audit repository.
        """
        self._traffic_service = traffic_service or TrafficService()
        self._incident_service = incident_service or IncidentService()
        self._route_service = route_service or RouteService()
        self._adapter = adapter or AISecOpsAdapter()

        # In-memory session query history for fallback & instant UI telemetry
        self._session_history: List[Dict[str, Any]] = []

        # Optional PostgreSQL audit repository
        self._audit_repo = audit_repo
        self._db_available: bool = False
        if self._audit_repo is None:
            self._init_postgres()
        else:
            self._db_available = True

    def _init_postgres(self) -> None:
        """Attempts to initialize PostgreSQL AuditRepository in a non-blocking manner."""
        try:
            db_mgr = PostgresConnectionManager()
            db_mgr.initialize()
            self._audit_repo = AuditRepository(db_mgr)
            self._db_available = True
            logger.info("ITSDashboardService successfully connected to PostgreSQL audit repository.")
        except Exception as exc:
            self._db_available = False
            self._audit_repo = None
            logger.warning(
                f"PostgreSQL audit repository unavailable (running in local in-memory session mode): {exc}"
            )

    @property
    def is_db_connected(self) -> bool:
        """Returns True if PostgreSQL audit storage is connected and active."""
        return self._db_available and self._audit_repo is not None

    @property
    def traffic_service(self) -> TrafficService:
        """Returns the domain TrafficService."""
        return self._traffic_service

    @property
    def incident_service(self) -> IncidentService:
        """Returns the domain IncidentService."""
        return self._incident_service

    @property
    def route_service(self) -> RouteService:
        """Returns the domain RouteService."""
        return self._route_service

    @property
    def adapter(self) -> AISecOpsAdapter:
        """Returns the security pipeline adapter."""
        return self._adapter

    # -------------------------------------------------------------------------
    # Domain Telemetry Retrieval
    # -------------------------------------------------------------------------

    def get_all_roads(self) -> List[Road]:
        """Returns all registered roads in the simulated network."""
        return self._route_service.get_all_roads()

    def get_all_traffic(self) -> List[TrafficCondition]:
        """Returns all current traffic conditions."""
        return self._traffic_service.get_all_traffic()

    def get_all_incidents(self) -> List[Incident]:
        """Returns all simulated incident records."""
        return self._incident_service.get_all_incidents()

    def get_active_incidents(self) -> List[Incident]:
        """Returns all currently active incidents."""
        return self._incident_service.get_active_incidents()

    def get_network_kpis(self) -> Dict[str, Any]:
        """
        Calculates holistic network status metrics across roads, traffic, and incidents.
        """
        roads = self.get_all_roads()
        traffic = self.get_all_traffic()
        incidents = self.get_all_incidents()
        active_incidents = [inc for inc in incidents if inc.status == "ACTIVE"]

        avg_speed = (
            sum(t.average_speed for t in traffic) / len(traffic)
            if traffic
            else 0.0
        )
        total_vehicles = sum(t.vehicle_count for t in traffic)
        critical_congestion = sum(1 for t in traffic if t.congestion_level == "CRITICAL")
        high_congestion = sum(1 for t in traffic if t.congestion_level == "HIGH")

        return {
            "total_roads": len(roads),
            "monitored_segments": len(traffic),
            "average_speed_kmh": round(avg_speed, 1),
            "total_vehicles": total_vehicles,
            "total_incidents": len(incidents),
            "active_incidents": len(active_incidents),
            "critical_congestion_count": critical_congestion,
            "high_congestion_count": high_congestion,
            "operational_roads": sum(1 for r in roads if r.status == "ACTIVE"),
        }

    def get_road_details_map(self) -> List[Dict[str, Any]]:
        """
        Combines road, traffic, and active incident details into a unified table representation.
        """
        roads = self.get_all_roads()
        combined: List[Dict[str, Any]] = []

        for road in roads:
            traffic = self._traffic_service.get_traffic_by_road(road.road_id)
            incidents = self._incident_service.get_active_incidents_by_road(road.road_id)

            combined.append({
                "road_id": road.road_id,
                "road_name": road.road_name,
                "road_type": road.road_type,
                "speed_limit_kmh": road.speed_limit,
                "status": road.status,
                "congestion_level": traffic.congestion_level if traffic else "UNKNOWN",
                "average_speed_kmh": traffic.average_speed if traffic else None,
                "vehicle_count": traffic.vehicle_count if traffic else None,
                "sensor_health": getattr(traffic, "sensor_health", "NORMAL (SIMULATED)"),
                "active_incidents_count": len(incidents),
                "incident_summaries": [f"{i.incident_type} ({i.severity})" for i in incidents],
            })

        return combined

    # -------------------------------------------------------------------------
    # Canonical AI Assistant Query Flow
    # -------------------------------------------------------------------------

    def process_query(
        self,
        user_query: str,
        user_id: str = "soc_operator",
        session_id: Optional[str] = None,
    ) -> ITSResponse:
        """
        Executes a transportation operator query through the canonical AISecOpsAdapter.

        Flow:
            Query → ITSContextBuilder → PipelineRequest → 8-Stage Security Pipeline → ITSResponse

        Returns:
            Structured ITSResponse DTO.
        """
        # Call the canonical adapter API
        response: ITSResponse = self._adapter.process_query(
            user_query=user_query,
            user_id=user_id,
            session_id=session_id,
        )

        # Record in local session query history for instant dashboard telemetry
        self._record_session_query(response)

        return response

    def execute_query(
        self,
        user_query: str,
        user_id: str = "soc_operator",
        session_id: Optional[str] = None,
    ) -> PipelineResponse:
        """
        Executes a query returning the underlying raw PipelineResponse directly.
        """
        return self._adapter.execute_query(
            user_query=user_query,
            user_id=user_id,
            session_id=session_id,
        )

    def _record_session_query(self, response: ITSResponse) -> None:
        """Records an execution event in local in-memory session history."""
        record = {
            "request_id": response.request_id,
            "trace_id": response.trace_id,
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "user_query": response.user_query,
            "decision": response.decision,
            "blocked": response.blocked,
            "blocked_by": response.blocked_by or "-",
            "risk_score": round(response.risk_score, 3),
            "risk_level": response.risk_level,
            "execution_time_ms": round(response.execution_time_ms, 2),
            "road_identified": response.its_context.road.road_name if response.its_context.road else "General/Network",
            "warnings": response.metadata.get("warnings", []),
            "stage_timings": response.metadata.get("stage_timings_ms", {}),
        }
        # Prepend latest
        self._session_history.insert(0, record)

    # -------------------------------------------------------------------------
    # Non-Blocking Security Telemetry & Audit
    # -------------------------------------------------------------------------

    def get_audit_telemetry(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Fetches recent security audit records.
        Prioritizes PostgreSQL AuditRepository if connected; falls back to session history.
        """
        if self.is_db_connected and self._audit_repo is not None:
            try:
                events = self._audit_repo.query_events(limit=limit)
                return [
                    {
                        "event_id": ev.event_id,
                        "request_id": ev.request_id,
                        "trace_id": ev.trace_id,
                        "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "component": ev.component,
                        "event_type": ev.event_type,
                        "severity": ev.severity,
                        "action": ev.action,
                        "status": ev.status,
                        "message": ev.message,
                        "source": "PostgreSQL",
                    }
                    for ev in events
                ]
            except Exception as exc:
                logger.warning(f"Error querying PostgreSQL audit events, falling back: {exc}")

        # Fallback: In-memory session history
        return [
            {
                "event_id": item["request_id"],
                "request_id": item["request_id"],
                "trace_id": item["trace_id"],
                "timestamp": item["timestamp"],
                "component": item.get("blocked_by") if item["blocked"] else "AISecOpsPipeline",
                "event_type": "SECURITY_DECISION",
                "severity": "CRITICAL" if item["blocked"] else "INFO",
                "action": "BLOCK" if item["blocked"] else "ALLOW",
                "status": item["decision"],
                "message": f"Query '{item['user_query'][:40]}...' decision: {item['decision']}",
                "source": "SessionMemory",
            }
            for item in self._session_history[:limit]
        ]

    def get_security_kpis(self) -> Dict[str, Any]:
        """
        Retrieves security summary metrics.
        Uses PostgreSQL summary if available, combined with session telemetry.
        """
        session_total = len(self._session_history)
        session_blocked = sum(1 for q in self._session_history if q["blocked"])
        session_allowed = session_total - session_blocked

        if self.is_db_connected and self._audit_repo is not None:
            try:
                db_stats = self._audit_repo.get_summary_stats()
                return {
                    "total_requests": db_stats.get("total_requests", session_total),
                    "allowed_requests": db_stats.get("allowed_requests", session_allowed),
                    "blocked_requests": db_stats.get("blocked_requests", session_blocked),
                    "high_risk_requests": db_stats.get("high_risk_requests", 0),
                    "db_status": "Online (PostgreSQL)",
                    "session_queries": session_total,
                }
            except Exception as exc:
                logger.warning(f"Error retrieving PostgreSQL security stats: {exc}")

        return {
            "total_requests": session_total,
            "allowed_requests": session_allowed,
            "blocked_requests": session_blocked,
            "high_risk_requests": session_blocked,
            "db_status": "Offline (Local Session Mode)",
            "session_queries": session_total,
        }

    def get_session_history(self) -> List[Dict[str, Any]]:
        """Returns the in-memory session query history."""
        return list(self._session_history)
