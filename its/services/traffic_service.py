"""
TrafficService — Simulated ITS traffic data retrieval service.

Loads and queries simulated traffic condition data.
Does NOT perform any security analysis or LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from its.loaders.base_loader import BaseITSDataLoader
from its.models.its_models import TrafficCondition, TrafficObservation


class TrafficService:
    """
    Service for loading and querying simulated or high-throughput traffic telemetry data.

    Reads from its/data/traffic.json by default or delegates to a BaseITSDataLoader
    (e.g., CSV, Parquet, PEMS-BAY, METR-LA).
    """

    def __init__(
        self,
        data_path: Optional[str] = None,
        loader: Optional[BaseITSDataLoader] = None,
    ) -> None:
        """
        Initializes the TrafficService with simulated or loaded traffic data.

        Args:
            data_path: Optional override path to traffic.json.
            loader: Optional BaseITSDataLoader instance.
        """
        self._loader = loader
        if data_path is None:
            data_path = str(Path(__file__).resolve().parent.parent / "data" / "traffic.json")
        self._data_path = data_path
        self._traffic_data: List[TrafficCondition] = []
        self._load_data()

    def _load_data(self) -> None:
        """Loads traffic data from the loader or JSON file."""
        if self._loader is not None:
            self._traffic_data = self._loader.get_all_traffic()
            return
        with open(self._data_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._traffic_data = [
            TrafficCondition.from_dict(entry) for entry in raw.get("traffic", [])
        ]

    def get_all_traffic(self) -> List[TrafficCondition]:
        """Returns all traffic condition records."""
        if self._loader is not None and not self._traffic_data:
            self._traffic_data = self._loader.get_all_traffic()
        return list(self._traffic_data)

    def get_traffic_by_road(self, road_id: str) -> Optional[TrafficCondition]:
        """
        Retrieves the traffic condition for a specific road or sensor ID.

        Args:
            road_id: The road identifier (e.g., 'RD-001') or sensor ID.

        Returns:
            TrafficCondition if found, None otherwise.
        """
        if self._loader is not None:
            latest = self._loader.get_latest_traffic(road_id)
            if latest:
                return latest
        for tc in self._traffic_data:
            if tc.road_id == road_id:
                return tc
        return None

    def get_roads_by_congestion(self, level: str) -> List[TrafficCondition]:
        """
        Retrieves all traffic conditions matching the specified congestion level.

        Args:
            level: Congestion level string (LOW, MEDIUM, HIGH, CRITICAL).

        Returns:
            List of matching TrafficCondition records.
        """
        return [tc for tc in self._traffic_data if tc.congestion_level == level.upper()]

    def get_traffic_summary(self) -> Dict[str, int]:
        """
        Calculates a basic summary of traffic conditions across all roads.

        Returns:
            Dictionary with counts by congestion level and total roads.
        """
        summary = {"total_roads": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for tc in self._traffic_data:
            summary["total_roads"] += 1
            level = tc.congestion_level.upper()
            if level in summary:
                summary[level] += 1
        return summary

    def stream_observations(self, chunk_size: int = 1000):
        """Streams normalized TrafficObservation chunks from the configured loader."""
        if self._loader is not None:
            yield from self._loader.stream_traffic_observations(chunk_size=chunk_size)
        else:
            from its.loaders.json_loader import JSONMockDataLoader
            default_loader = JSONMockDataLoader(traffic_path=self._data_path)
            yield from default_loader.stream_traffic_observations(chunk_size=chunk_size)

    def get_dataset_metadata(self):
        """Returns metadata regarding the active traffic data source."""
        if self._loader is not None:
            return self._loader.get_metadata()
        from its.loaders.json_loader import JSONMockDataLoader
        return JSONMockDataLoader(traffic_path=self._data_path).get_metadata()

