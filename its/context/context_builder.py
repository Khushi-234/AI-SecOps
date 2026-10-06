"""
ITSContextBuilder — Domain Context Assembler for ITS Queries.

This is the most important new component in the ITS application layer.
Its SOLE responsibility is to combine:
    1. A user's transportation query
    2. Relevant ITS data (roads, traffic, incidents)

into a structured ITSContext object.

CRITICAL DESIGN CONSTRAINTS — This module MUST NOT:
    - Detect prompt injection
    - Calculate security risk scores
    - Make policy decisions (allow/block)
    - Call any LLM or LLM Provider directly
    - Bypass the AI-SecOps pipeline
    - Construct a final LLM prompt (that's the Prompt Builder's job)

Its only job is DOMAIN CONTEXT CONSTRUCTION.

Architecture Flow:
    User Query → ITSContextBuilder → ITSContext → AI-SecOps Pipeline Entry Point
"""

from __future__ import annotations

from typing import Any, List, Optional

from its.models.its_models import ITSContext, Incident, Road, TrafficCondition
from its.services.incident_service import IncidentService
from its.services.route_service import RouteService
from its.services.traffic_service import TrafficService


class ITSContextBuilder:
    """
    Assembles domain-specific transportation context for user queries.

    Combines user query text with relevant ITS telemetry data
    (road info, traffic conditions, active incidents) into a
    structured ITSContext object.

    The resulting context is intended to be passed to the existing
    AI-SecOps pipeline's Prompt Builder — NOT directly to an LLM.
    """

    def __init__(
        self,
        route_service: Optional[RouteService] = None,
        traffic_service: Optional[TrafficService] = None,
        incident_service: Optional[IncidentService] = None,
        loader: Optional[Any] = None,
    ) -> None:
        """
        Initializes the context builder with ITS data services.

        Args:
            route_service: Service for road/route data. Auto-created if None.
            traffic_service: Service for traffic condition data. Auto-created if None.
            incident_service: Service for incident data. Auto-created if None.
            loader: Optional BaseITSDataLoader instance to seed services.
        """
        if loader is not None:
            self._route_service = route_service or RouteService(loader=loader)
            self._traffic_service = traffic_service or TrafficService(loader=loader)
            self._incident_service = incident_service or IncidentService(loader=loader)
        else:
            self._route_service = route_service or RouteService()
            self._traffic_service = traffic_service or TrafficService()
            self._incident_service = incident_service or IncidentService()
        self._loader = loader

    def build_context(self, user_query: str) -> ITSContext:
        """
        Builds an ITSContext by extracting relevant transportation data
        based on the user's query.

        Args:
            user_query: The user's natural language transportation query.

        Returns:
            ITSContext containing the user query and relevant ITS data.
        """
        # Identify which road the user is asking about
        road = self._identify_road(user_query)

        # Retrieve traffic conditions for the identified road
        traffic: Optional[TrafficCondition] = None
        if road:
            traffic = self._traffic_service.get_traffic_by_road(road.road_id)

        # Retrieve active incidents for the identified road
        incidents: List[Incident] = []
        if road:
            incidents = self._incident_service.get_active_incidents_by_road(road.road_id)

        # Build a summary description
        summary = self._build_summary(road, traffic, incidents, user_query)

        context = ITSContext(
            user_query=user_query,
            road=road,
            traffic=traffic,
            incidents=incidents,
            summary=summary,
            metadata={
                "source": "SIMULATED ITS TELEMETRY",
                "road_identified": road is not None,
                "road_name": road.road_name if road else None,
                "total_active_incidents": len(incidents),
            },
        )

        return context

    def build_general_context(self, user_query: str) -> ITSContext:
        """
        Builds an ITSContext with a broad overview of the transportation network.

        Used when the query does not reference a specific road but asks
        about the general transportation state (e.g., "Which roads have high congestion?").

        Args:
            user_query: The user's natural language query.

        Returns:
            ITSContext with network-wide traffic and incident summaries.
        """
        all_traffic = self._traffic_service.get_all_traffic()
        active_incidents = self._incident_service.get_active_incidents()
        traffic_summary = self._traffic_service.get_traffic_summary()

        # Build a comprehensive summary
        summary_parts = [
            f"Network Overview: {traffic_summary['total_roads']} monitored roads.",
            f"Congestion — LOW: {traffic_summary['LOW']}, MEDIUM: {traffic_summary['MEDIUM']}, "
            f"HIGH: {traffic_summary['HIGH']}, CRITICAL: {traffic_summary['CRITICAL']}.",
            f"Active Incidents: {len(active_incidents)}.",
        ]

        context = ITSContext(
            user_query=user_query,
            road=None,
            traffic=None,
            incidents=active_incidents,
            summary=" ".join(summary_parts),
            metadata={
                "source": "SIMULATED ITS TELEMETRY",
                "query_type": "general_overview",
                "traffic_summary": traffic_summary,
                "total_active_incidents": len(active_incidents),
            },
        )

        return context

    def _identify_road(self, query: str) -> Optional[Road]:
        """
        Identifies which road the user is asking about based on keyword matching.

        Uses case-insensitive matching against known road names.

        Args:
            query: The user's query string.

        Returns:
            Matching Road if found, None otherwise.
        """
        query_lower = query.lower()
        all_roads = self._route_service.get_all_roads()

        for road in all_roads:
            if road.road_name.lower() in query_lower or road.road_id.lower() in query_lower:
                return road
            base_name = road.road_name.split("(")[0].strip().lower()
            if len(base_name) >= 3 and base_name in query_lower:
                return road

        return None

    def _build_summary(
        self,
        road: Optional[Road],
        traffic: Optional[TrafficCondition],
        incidents: List[Incident],
        user_query: str,
    ) -> str:
        """
        Constructs a human-readable summary of the identified ITS context.

        Args:
            road: The identified road (may be None).
            traffic: Traffic conditions for the road (may be None).
            incidents: Active incidents on the road.
            user_query: Original user query.

        Returns:
            Summary string describing the transportation context.
        """
        if road is None:
            return (
                "No specific road identified in the query. "
                "General transportation network context may be needed."
            )

        parts = [f"Road: {road.road_name} ({road.start_location} → {road.end_location})."]

        if traffic:
            parts.append(
                f"Traffic: {traffic.vehicle_count} vehicles, "
                f"avg speed {traffic.average_speed} km/h, "
                f"congestion {traffic.congestion_level}."
            )

        if incidents:
            incident_types = [inc.incident_type for inc in incidents]
            parts.append(
                f"Active incidents: {len(incidents)} — {', '.join(incident_types)}."
            )
        else:
            parts.append("No active incidents reported.")

        return " ".join(parts)
