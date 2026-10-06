"""
JSONMockDataLoader — Adapter for simulated JSON smoke-test datasets.

Maintains complete backward compatibility with roads.json, traffic.json,
and incidents.json while fulfilling the BaseITSDataLoader contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from its.loaders.base_loader import BaseITSDataLoader
from its.models.its_models import (
    DatasetMetadata,
    Incident,
    Road,
    TrafficCondition,
    TrafficObservation,
)


class JSONMockDataLoader(BaseITSDataLoader):
    """
    Adapter for loading and streaming standard JSON ITS telemetry.
    """

    def __init__(
        self,
        roads_path: Optional[str] = None,
        traffic_path: Optional[str] = None,
        incidents_path: Optional[str] = None,
    ) -> None:
        data_dir = Path(__file__).resolve().parent.parent / "data"
        self._roads_path = Path(roads_path) if roads_path else data_dir / "roads.json"
        self._traffic_path = Path(traffic_path) if traffic_path else data_dir / "traffic.json"
        self._incidents_path = Path(incidents_path) if incidents_path else data_dir / "incidents.json"

        self._roads: List[Road] = []
        self._traffic: Dict[str, TrafficCondition] = {}
        self._observations: List[TrafficObservation] = []
        self._incidents: List[Incident] = []

        self._load_data()

    def _load_data(self) -> None:
        """Loads and parses JSON fixtures."""
        if self._roads_path.exists():
            with open(self._roads_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self._roads = [Road.from_dict(entry) for entry in raw.get("roads", [])]

        if self._traffic_path.exists():
            with open(self._traffic_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                entries = raw.get("traffic", [])
                for entry in entries:
                    cond = TrafficCondition.from_dict(entry)
                    self._traffic[cond.road_id] = cond

                    # Map road coordinates if available
                    matching_road = next((r for r in self._roads if r.road_id == cond.road_id), None)
                    obs = TrafficObservation(
                        sensor_id=cond.road_id,
                        road_id=cond.road_id,
                        timestamp=cond.timestamp,
                        speed=float(cond.average_speed),
                        flow=float(cond.vehicle_count),
                        occupancy=None,
                        congestion_level=cond.congestion_level,
                        latitude=matching_road.latitude if matching_road else None,
                        longitude=matching_road.longitude if matching_road else None,
                    )
                    self._observations.append(obs)

        if self._incidents_path.exists():
            with open(self._incidents_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self._incidents = [Incident.from_dict(entry) for entry in raw.get("incidents", [])]

    def load_roads(self) -> List[Road]:
        """Returns all loaded roads."""
        return list(self._roads)

    def load_incidents(self) -> List[Incident]:
        """Returns all loaded incidents."""
        return list(self._incidents)

    def stream_traffic_observations(
        self, chunk_size: int = 1000
    ) -> Iterator[List[TrafficObservation]]:
        """Yields traffic observations in chunks."""
        total = len(self._observations)
        for i in range(0, total, chunk_size):
            yield self._observations[i : i + chunk_size]

    def get_latest_traffic(self, road_or_sensor_id: str) -> Optional[TrafficCondition]:
        """Returns the traffic condition for a given road or sensor ID."""
        return self._traffic.get(road_or_sensor_id)

    def get_all_traffic(self) -> List[TrafficCondition]:
        """Returns all loaded traffic conditions."""
        return list(self._traffic.values())

    def get_metadata(self) -> DatasetMetadata:
        """Returns metadata for the mock JSON dataset."""
        return DatasetMetadata(
            name="Mock JSON Transportation Dataset",
            format="json",
            total_records=len(self._observations),
            num_sensors=len(self._traffic),
            time_range="Static Simulated Snapshot",
            features=["vehicle_count", "average_speed", "congestion_level"],
            metadata={"source": "simulated_telemetry", "files": [str(self._roads_path), str(self._traffic_path)]},
        )
