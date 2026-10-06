"""
ITS Unit Tests — Validates the ITS data model, services, and context builder.

These tests verify:
1. Simulated data loads correctly
2. Services return expected results
3. Context builder assembles correct domain context
4. No security logic leaks into the ITS layer
"""

from __future__ import annotations

import pytest
from pathlib import Path

from its.models.its_models import (
    Road,
    TrafficCondition,
    Incident,
    ITSContext,
    CongestionLevel,
    IncidentType,
)
from its.services.route_service import RouteService
from its.services.traffic_service import TrafficService
from its.services.incident_service import IncidentService
from its.context.context_builder import ITSContextBuilder


# =========================================================================
# Data Loading Tests
# =========================================================================

class TestDataLoading:
    """Verifies that simulated ITS data files load correctly."""

    def test_roads_data_loads(self):
        """roads.json should load and return Road objects."""
        service = RouteService()
        roads = service.get_all_roads()
        assert len(roads) > 0, "Expected at least one road"
        assert isinstance(roads[0], Road)

    def test_traffic_data_loads(self):
        """traffic.json should load and return TrafficCondition objects."""
        service = TrafficService()
        traffic = service.get_all_traffic()
        assert len(traffic) > 0, "Expected at least one traffic record"
        assert isinstance(traffic[0], TrafficCondition)

    def test_incidents_data_loads(self):
        """incidents.json should load and return Incident objects."""
        service = IncidentService()
        incidents = service.get_all_incidents()
        assert len(incidents) > 0, "Expected at least one incident"
        assert isinstance(incidents[0], Incident)

    def test_roads_have_required_fields(self):
        """Each road should have all required fields populated."""
        service = RouteService()
        for road in service.get_all_roads():
            assert road.road_id, "road_id must not be empty"
            assert road.road_name, "road_name must not be empty"
            assert road.speed_limit > 0, "speed_limit must be positive"
            assert road.status, "status must not be empty"

    def test_traffic_has_valid_congestion_levels(self):
        """All traffic congestion levels must be valid enum values."""
        valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        service = TrafficService()
        for tc in service.get_all_traffic():
            assert tc.congestion_level in valid_levels, (
                f"Invalid congestion level: {tc.congestion_level}"
            )

    def test_incidents_have_valid_types(self):
        """All incident types must be valid enum values."""
        valid_types = {"ACCIDENT", "ROAD_BLOCK", "CONSTRUCTION", "VEHICLE_BREAKDOWN", "TRAFFIC_JAM"}
        service = IncidentService()
        for inc in service.get_all_incidents():
            assert inc.incident_type in valid_types, (
                f"Invalid incident type: {inc.incident_type}"
            )


# =========================================================================
# Route Service Tests
# =========================================================================

class TestRouteService:
    """Tests for the RouteService."""

    def test_get_road_by_id(self):
        """Should find a road by its ID."""
        service = RouteService()
        road = service.get_road_by_id("RD-001")
        assert road is not None
        assert road.road_name == "SG Highway"

    def test_get_road_by_name(self):
        """Should find a road by partial name match."""
        service = RouteService()
        road = service.get_road_by_name("SG Highway")
        assert road is not None
        assert road.road_id == "RD-001"

    def test_get_road_by_name_case_insensitive(self):
        """Road name search should be case-insensitive."""
        service = RouteService()
        road = service.get_road_by_name("sg highway")
        assert road is not None
        assert road.road_id == "RD-001"

    def test_get_nonexistent_road_returns_none(self):
        """Searching for a road that doesn't exist should return None."""
        service = RouteService()
        assert service.get_road_by_id("RD-999") is None
        assert service.get_road_by_name("Nonexistent Road") is None

    def test_get_road_names(self):
        """Should return a list of all road names."""
        service = RouteService()
        names = service.get_road_names()
        assert "SG Highway" in names
        assert "Ring Road" in names
        assert "Airport Road" in names

    def test_network_summary(self):
        """Should return a valid network summary dict."""
        service = RouteService()
        summary = service.get_network_summary()
        assert summary["total_roads"] > 0


# =========================================================================
# Traffic Service Tests
# =========================================================================

class TestTrafficService:
    """Tests for the TrafficService."""

    def test_get_traffic_by_road(self):
        """Should find traffic data for a specific road."""
        service = TrafficService()
        tc = service.get_traffic_by_road("RD-001")
        assert tc is not None
        assert tc.vehicle_count > 0

    def test_get_roads_by_congestion(self):
        """Should filter roads by congestion level."""
        service = TrafficService()
        high_congestion = service.get_roads_by_congestion("HIGH")
        assert len(high_congestion) > 0
        for tc in high_congestion:
            assert tc.congestion_level == "HIGH"

    def test_traffic_summary(self):
        """Should return a valid traffic summary."""
        service = TrafficService()
        summary = service.get_traffic_summary()
        assert summary["total_roads"] > 0
        total_by_level = summary["LOW"] + summary["MEDIUM"] + summary["HIGH"] + summary["CRITICAL"]
        assert total_by_level == summary["total_roads"]


# =========================================================================
# Incident Service Tests
# =========================================================================

class TestIncidentService:
    """Tests for the IncidentService."""

    def test_get_active_incidents(self):
        """Should return only active incidents."""
        service = IncidentService()
        active = service.get_active_incidents()
        for inc in active:
            assert inc.status == "ACTIVE"

    def test_get_incidents_by_road(self):
        """Should filter incidents by road ID."""
        service = IncidentService()
        incidents = service.get_incidents_by_road("RD-001")
        for inc in incidents:
            assert inc.road_id == "RD-001"

    def test_get_active_incidents_by_road(self):
        """Should return only active incidents for a specific road."""
        service = IncidentService()
        active = service.get_active_incidents_by_road("RD-001")
        for inc in active:
            assert inc.road_id == "RD-001"
            assert inc.status == "ACTIVE"

    def test_incident_summary(self):
        """Should return a valid incident summary."""
        service = IncidentService()
        summary = service.get_incident_summary()
        assert summary["total"] > 0
        assert summary["active"] + summary["resolved"] == summary["total"]


# =========================================================================
# Context Builder Tests
# =========================================================================

class TestITSContextBuilder:
    """Tests for the ITSContextBuilder."""

    def test_build_context_specific_road(self):
        """Should build context with road, traffic, and incident data."""
        builder = ITSContextBuilder()
        ctx = builder.build_context("What is the traffic condition on SG Highway?")

        assert isinstance(ctx, ITSContext)
        assert ctx.user_query == "What is the traffic condition on SG Highway?"
        assert ctx.road is not None
        assert ctx.road.road_name == "SG Highway"
        assert ctx.traffic is not None
        assert ctx.traffic.congestion_level == "HIGH"
        assert len(ctx.incidents) > 0

    def test_build_context_unknown_road(self):
        """Should handle queries where no road is identified."""
        builder = ITSContextBuilder()
        ctx = builder.build_context("What is the weather today?")

        assert isinstance(ctx, ITSContext)
        assert ctx.road is None
        assert ctx.traffic is None
        assert len(ctx.incidents) == 0

    def test_build_general_context(self):
        """Should build network-wide context for general queries."""
        builder = ITSContextBuilder()
        ctx = builder.build_general_context("Which roads have high congestion?")

        assert isinstance(ctx, ITSContext)
        assert ctx.road is None  # General context doesn't target a specific road
        assert len(ctx.incidents) > 0  # Should include all active incidents
        assert "Network Overview" in ctx.summary

    def test_to_prompt_context_format(self):
        """to_prompt_context should produce a formatted text block."""
        builder = ITSContextBuilder()
        ctx = builder.build_context("What is the traffic condition on SG Highway?")
        prompt_ctx = ctx.to_prompt_context()

        assert isinstance(prompt_ctx, str)
        assert "SIMULATED ITS TELEMETRY" in prompt_ctx
        assert "SG Highway" in prompt_ctx
        assert "Vehicle Count" in prompt_ctx

    def test_context_does_not_contain_security_logic(self):
        """ITSContext must not contain security-related fields or decisions."""
        builder = ITSContextBuilder()
        ctx = builder.build_context("What is the traffic condition on SG Highway?")

        # Verify no security-related attributes exist
        assert not hasattr(ctx, "risk_score")
        assert not hasattr(ctx, "risk_level")
        assert not hasattr(ctx, "policy_decision")
        assert not hasattr(ctx, "is_blocked")
        assert not hasattr(ctx, "threat_type")

    def test_context_to_dict(self):
        """to_dict should serialize the context to a dictionary."""
        builder = ITSContextBuilder()
        ctx = builder.build_context("What is the traffic condition on SG Highway?")
        d = ctx.to_dict()

        assert isinstance(d, dict)
        assert "user_query" in d
        assert "road" in d
        assert "traffic" in d
        assert "incidents" in d
        assert d["metadata"]["source"] == "SIMULATED ITS TELEMETRY"

    def test_multiple_roads_identified_correctly(self):
        """Should correctly identify different roads from different queries."""
        builder = ITSContextBuilder()

        ctx1 = builder.build_context("Traffic on Ring Road")
        assert ctx1.road is not None
        assert ctx1.road.road_name == "Ring Road"

        ctx2 = builder.build_context("Incidents on Airport Road")
        assert ctx2.road is not None
        assert ctx2.road.road_name == "Airport Road"

        ctx3 = builder.build_context("University Road conditions")
        assert ctx3.road is not None
        assert ctx3.road.road_name == "University Road"
