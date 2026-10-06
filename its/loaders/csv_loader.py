"""
CSVTrafficDataLoader — Streaming and chunked ingestion adapter for CSV traffic datasets.

Enables processing large-scale CSV traffic files (multi-gigabyte, millions of rows)
in a chunked streaming fashion without loading the entire dataset into memory.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from its.loaders.base_loader import BaseITSDataLoader
from its.models.its_models import (
    DatasetMetadata,
    Incident,
    Road,
    TrafficCondition,
    TrafficObservation,
)


class CSVTrafficDataLoader(BaseITSDataLoader):
    """
    Streaming CSV data loader capable of processing millions of rows in chunks.
    """

    def __init__(
        self,
        csv_path: Union[str, Path],
        roads_path: Optional[Union[str, Path]] = None,
        incidents_path: Optional[Union[str, Path]] = None,
        name: str = "CSV Traffic Dataset",
        default_speed_limit: float = 65.0,
    ) -> None:
        self._csv_path = Path(csv_path)
        self._roads_path = Path(roads_path) if roads_path else None
        self._incidents_path = Path(incidents_path) if incidents_path else None
        self._name = name
        self._default_speed_limit = default_speed_limit

        self._roads: List[Road] = []
        self._incidents: List[Incident] = []
        self._latest_cache: Dict[str, TrafficCondition] = {}
        self._total_rows: Optional[int] = None
        self._unique_sensors: set[str] = set()

        self._init_metadata()

    def _init_metadata(self) -> None:
        """Loads optional roads/incidents if provided."""
        if self._roads_path and self._roads_path.exists():
            import json
            with open(self._roads_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self._roads = [Road.from_dict(entry) for entry in raw.get("roads", [])]

        if self._incidents_path and self._incidents_path.exists():
            import json
            with open(self._incidents_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self._incidents = [Incident.from_dict(entry) for entry in raw.get("incidents", [])]

    def load_roads(self) -> List[Road]:
        """Returns registered roads or generates synthetic road objects from unique sensors."""
        if self._roads:
            return list(self._roads)

        # Fallback: create road entries for discovered sensors
        roads = []
        for sensor_id in sorted(self._unique_sensors):
            roads.append(
                Road(
                    road_id=sensor_id,
                    road_name=f"Corridor {sensor_id}",
                    start_location=f"Sensor {sensor_id} Ingress",
                    end_location=f"Sensor {sensor_id} Egress",
                    latitude=0.0,
                    longitude=0.0,
                    speed_limit=int(self._default_speed_limit),
                    lanes=3,
                    length_km=1.0,
                    road_type="HIGHWAY",
                    status="ACTIVE",
                )
            )
        return roads

    def load_incidents(self) -> List[Incident]:
        """Returns loaded incidents."""
        return list(self._incidents)

    def _normalize_row(self, row: Dict[str, Any]) -> TrafficObservation:
        """Maps varied CSV header column names to TrafficObservation fields."""
        sensor_id = str(
            row.get("sensor_id")
            or row.get("sensor")
            or row.get("road_id")
            or row.get("id")
            or "SENSOR_UNKNOWN"
        )
        timestamp = str(
            row.get("timestamp")
            or row.get("time")
            or row.get("datetime")
            or row.get("date")
            or ""
        )
        try:
            speed = float(row.get("speed") or row.get("average_speed") or row.get("traffic_speed") or 0.0)
        except (ValueError, TypeError):
            speed = 0.0

        flow = None
        for k in ("flow", "vehicle_count", "volume", "traffic_flow"):
            if row.get(k) is not None and row.get(k) != "":
                try:
                    flow = float(row[k])
                    break
                except (ValueError, TypeError):
                    pass

        occupancy = None
        for k in ("occupancy", "occ"):
            if row.get(k) is not None and row.get(k) != "":
                try:
                    occupancy = float(row[k])
                    break
                except (ValueError, TypeError):
                    pass

        lat = None
        for k in ("latitude", "lat"):
            if row.get(k) is not None and row.get(k) != "":
                try:
                    lat = float(row[k])
                    break
                except (ValueError, TypeError):
                    pass

        lon = None
        for k in ("longitude", "lon", "lng"):
            if row.get(k) is not None and row.get(k) != "":
                try:
                    lon = float(row[k])
                    break
                except (ValueError, TypeError):
                    pass

        c_level = self.calculate_congestion_level(
            speed=speed,
            speed_limit=self._default_speed_limit,
            occupancy=occupancy,
        )

        obs = TrafficObservation(
            sensor_id=sensor_id,
            road_id=sensor_id,
            timestamp=timestamp,
            speed=speed,
            flow=flow,
            occupancy=occupancy,
            congestion_level=c_level.value,
            latitude=lat,
            longitude=lon,
        )
        return obs

    def stream_traffic_observations(
        self, chunk_size: int = 1000
    ) -> Iterator[List[TrafficObservation]]:
        """
        Streams CSV records in chunks using pandas or csv.DictReader.
        Keeps memory consumption constant regardless of file size.
        """
        if not self._csv_path.exists():
            return

        try:
            import pandas as pd
            reader = pd.read_csv(self._csv_path, chunksize=chunk_size)
            for df_chunk in reader:
                chunk: List[TrafficObservation] = []
                for _, row in df_chunk.iterrows():
                    obs = self._normalize_row(row.to_dict())
                    self._unique_sensors.add(obs.sensor_id)
                    self._latest_cache[obs.sensor_id] = obs.to_traffic_condition()
                    chunk.append(obs)
                yield chunk
        except Exception:
            # Fallback to standard csv streaming
            with open(self._csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                chunk = []
                for row in reader:
                    obs = self._normalize_row(row)
                    self._unique_sensors.add(obs.sensor_id)
                    self._latest_cache[obs.sensor_id] = obs.to_traffic_condition()
                    chunk.append(obs)
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk

    def get_latest_traffic(self, road_or_sensor_id: str) -> Optional[TrafficCondition]:
        """Returns the most recent traffic condition for a given sensor or road ID."""
        if road_or_sensor_id in self._latest_cache:
            return self._latest_cache[road_or_sensor_id]

        # Scan streaming data to find and cache
        for chunk in self.stream_traffic_observations(chunk_size=2000):
            for obs in chunk:
                if obs.sensor_id == road_or_sensor_id or obs.road_id == road_or_sensor_id:
                    self._latest_cache[road_or_sensor_id] = obs.to_traffic_condition()
            if road_or_sensor_id in self._latest_cache:
                return self._latest_cache[road_or_sensor_id]

        return None

    def get_metadata(self) -> DatasetMetadata:
        """Returns dataset metadata."""
        size_bytes = self._csv_path.stat().st_size if self._csv_path.exists() else 0
        return DatasetMetadata(
            name=self._name,
            format="csv",
            total_records=self._total_rows or 0,
            num_sensors=len(self._unique_sensors),
            time_range="Time-Series Streaming Range",
            features=["sensor_id", "timestamp", "speed", "flow", "occupancy"],
            metadata={"file_path": str(self._csv_path), "file_size_bytes": size_bytes},
        )
