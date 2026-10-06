"""
IncidentService — Simulated ITS incident data retrieval service.

Loads and queries simulated transportation incident data.
Does NOT perform any security analysis or LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from its.loaders.base_loader import BaseITSDataLoader
from its.models.its_models import Incident


class IncidentService:
    """
    Service for loading and querying simulated incident telemetry data.

    Reads from its/data/incidents.json and provides lookup methods
    for incidents by road ID, status, and type.
    """

    def __init__(
        self,
        data_path: Optional[str] = None,
        loader: Optional[BaseITSDataLoader] = None,
    ) -> None:
        """
        Initializes the IncidentService with the simulated or loaded incident data.

        Args:
            data_path: Optional override path to incidents.json.
            loader: Optional BaseITSDataLoader instance.
        """
        self._loader = loader
        if data_path is None:
            data_path = str(Path(__file__).resolve().parent.parent / "data" / "incidents.json")
        self._data_path = data_path
        self._incidents: List[Incident] = []
        self._load_data()

    def _load_data(self) -> None:
        """Loads incident data from the loader or JSON file."""
        if self._loader is not None:
            self._incidents = self._loader.load_incidents()
            return
        with open(self._data_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._incidents = [
            Incident.from_dict(entry) for entry in raw.get("incidents", [])
        ]

    def get_all_incidents(self) -> List[Incident]:
        """Returns all incident records."""
        return list(self._incidents)

    def get_incidents_by_road(self, road_id: str) -> List[Incident]:
        """
        Retrieves all incidents for a specific road.

        Args:
            road_id: The road identifier (e.g., 'RD-001').

        Returns:
            List of Incident records for the specified road.
        """
        return [inc for inc in self._incidents if inc.road_id == road_id]

    def get_active_incidents(self) -> List[Incident]:
        """Returns all currently active incidents."""
        return [inc for inc in self._incidents if inc.status == "ACTIVE"]

    def get_active_incidents_by_road(self, road_id: str) -> List[Incident]:
        """Returns active incidents for a specific road."""
        return [
            inc for inc in self._incidents
            if inc.road_id == road_id and inc.status == "ACTIVE"
        ]

    def get_incidents_by_type(self, incident_type: str) -> List[Incident]:
        """Retrieves incidents matching the specified type."""
        return [inc for inc in self._incidents if inc.incident_type == incident_type.upper()]

    def get_incidents_by_severity(self, severity: str) -> List[Incident]:
        """Retrieves incidents matching the specified severity level."""
        return [inc for inc in self._incidents if inc.severity == severity.upper()]

    def get_incident_summary(self) -> Dict[str, int]:
        """
        Calculates a summary of incidents by status and type.

        Returns:
            Dictionary with counts by status and type.
        """
        summary: Dict[str, int] = {
            "total": len(self._incidents),
            "active": 0,
            "resolved": 0,
            "ACCIDENT": 0,
            "ROAD_BLOCK": 0,
            "CONSTRUCTION": 0,
            "VEHICLE_BREAKDOWN": 0,
            "TRAFFIC_JAM": 0,
        }
        for inc in self._incidents:
            if inc.status == "ACTIVE":
                summary["active"] += 1
            elif inc.status == "RESOLVED":
                summary["resolved"] += 1
            inc_type = inc.incident_type.upper()
            if inc_type in summary:
                summary[inc_type] += 1
        return summary
