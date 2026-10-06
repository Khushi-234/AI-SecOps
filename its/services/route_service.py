"""
RouteService — Simulated ITS road/route information service.

Loads and queries simulated road network data.
Does NOT implement complex routing algorithms at this stage.
Does NOT perform any security analysis or LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from its.loaders.base_loader import BaseITSDataLoader
from its.models.its_models import Road


class RouteService:
    """
    Service for loading and querying simulated road network data.

    Reads from its/data/roads.json and provides lookup methods
    for road information by ID or name.
    """

    def __init__(
        self,
        data_path: Optional[str] = None,
        loader: Optional[BaseITSDataLoader] = None,
    ) -> None:
        """
        Initializes the RouteService with simulated or loaded road data.

        Args:
            data_path: Optional override path to roads.json.
            loader: Optional BaseITSDataLoader instance.
        """
        self._loader = loader
        if data_path is None:
            data_path = str(Path(__file__).resolve().parent.parent / "data" / "roads.json")
        self._data_path = data_path
        self._roads: List[Road] = []
        self._load_data()

    def _load_data(self) -> None:
        """Loads road data from the loader or JSON file."""
        if self._loader is not None:
            self._roads = self._loader.load_roads()
            return
        with open(self._data_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._roads = [Road.from_dict(entry) for entry in raw.get("roads", [])]

    def get_all_roads(self) -> List[Road]:
        """Returns all road records."""
        return list(self._roads)

    def get_road_by_id(self, road_id: str) -> Optional[Road]:
        """
        Retrieves a road by its identifier.

        Args:
            road_id: The road identifier (e.g., 'RD-001').

        Returns:
            Road if found, None otherwise.
        """
        for road in self._roads:
            if road.road_id == road_id:
                return road
        return None

    def get_road_by_name(self, road_name: str) -> Optional[Road]:
        """
        Retrieves a road by name (case-insensitive partial match).

        Args:
            road_name: Full or partial road name to search for.

        Returns:
            First matching Road if found, None otherwise.
        """
        name_lower = road_name.lower()
        for road in self._roads:
            if name_lower in road.road_name.lower():
                return road
        return None

    def get_roads_by_status(self, status: str) -> List[Road]:
        """Retrieves all roads matching the specified operational status."""
        return [road for road in self._roads if road.status == status.upper()]

    def get_road_names(self) -> List[str]:
        """Returns a list of all road names in the network."""
        return [road.road_name for road in self._roads]

    def get_network_summary(self) -> Dict[str, int]:
        """
        Returns a summary of the road network.

        Returns:
            Dictionary with total road count and counts by type/status.
        """
        summary: Dict[str, int] = {
            "total_roads": len(self._roads),
            "active": 0,
            "closed": 0,
            "maintenance": 0,
        }
        for road in self._roads:
            status_key = road.status.lower()
            if status_key in summary:
                summary[status_key] += 1
        return summary
