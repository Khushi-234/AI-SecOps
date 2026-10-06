"""
ParquetTrafficDataLoader — High-throughput columnar chunked reader for Parquet traffic files.

Supports trip-level datasets (e.g. NYC TLC Taxi trips) and sensor-level columnar datasets
via pyarrow / pandas streaming batches with zero unnecessary memory copies.
"""

from __future__ import annotations

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


class ParquetTrafficDataLoader(BaseITSDataLoader):
    """
    Columnar Parquet data loader processing large datasets in streaming batches.
    """

    def __init__(
        self,
        parquet_path: Union[str, Path],
        roads_path: Optional[Union[str, Path]] = None,
        incidents_path: Optional[Union[str, Path]] = None,
        name: str = "Parquet Traffic Dataset",
        default_speed_limit: float = 65.0,
    ) -> None:
        self._parquet_path = Path(parquet_path)
        self._roads_path = Path(roads_path) if roads_path else None
        self._incidents_path = Path(incidents_path) if incidents_path else None
        self._name = name
        self._default_speed_limit = default_speed_limit

        self._roads: List[Road] = []
        self._incidents: List[Incident] = []
        self._latest_cache: Dict[str, TrafficCondition] = {}
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
        """Returns loaded roads or generated corridors."""
        if self._roads:
            return list(self._roads)

        roads = []
        for sensor_id in sorted(self._unique_sensors):
            roads.append(
                Road(
                    road_id=sensor_id,
                    road_name=f"Corridor {sensor_id}",
                    start_location=f"Node {sensor_id} Ingress",
                    end_location=f"Node {sensor_id} Egress",
                    latitude=0.0,
                    longitude=0.0,
                    speed_limit=int(self._default_speed_limit),
                    lanes=3,
                    length_km=1.5,
                    road_type="HIGHWAY",
                    status="ACTIVE",
                )
            )
        return roads

    def load_incidents(self) -> List[Incident]:
        """Returns loaded incidents."""
        return list(self._incidents)

    def _normalize_record(self, record: Dict[str, Any]) -> TrafficObservation:
        """Maps diverse Parquet column schemas (sensor matrices or trip records) to TrafficObservation."""
        # Check for trip schemas (e.g. NYC TLC) vs sensor schemas
        sensor_id = str(
            record.get("sensor_id")
            or record.get("PULocationID")
            or record.get("road_id")
            or record.get("id")
            or "SENSOR_UNKNOWN"
        )
        timestamp = str(
            record.get("timestamp")
            or record.get("tpep_pickup_datetime")
            or record.get("pickup_datetime")
            or record.get("time")
            or ""
        )

        speed = 0.0
        if "speed" in record:
            try:
                speed = float(record["speed"])
            except (ValueError, TypeError):
                pass
        elif "trip_distance" in record and "trip_duration_hours" in record:
            try:
                dur = float(record["trip_duration_hours"])
                dist = float(record["trip_distance"])
                speed = (dist / dur) if dur > 0 else 30.0
            except (ValueError, TypeError):
                speed = 30.0
        elif "trip_distance" in record:
            try:
                speed = float(record["trip_distance"]) * 10.0
            except (ValueError, TypeError):
                speed = 35.0

        flow = None
        for k in ("flow", "passenger_count", "vehicle_count", "volume"):
            if record.get(k) is not None:
                try:
                    flow = float(record[k])
                    break
                except (ValueError, TypeError):
                    pass

        occupancy = None
        for k in ("occupancy", "occ"):
            if record.get(k) is not None:
                try:
                    occupancy = float(record[k])
                    break
                except (ValueError, TypeError):
                    pass

        lat = float(record["latitude"]) if record.get("latitude") is not None else None
        lon = float(record["longitude"]) if record.get("longitude") is not None else None

        c_level = self.calculate_congestion_level(
            speed=speed,
            speed_limit=self._default_speed_limit,
            occupancy=occupancy,
        )

        return TrafficObservation(
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

    def stream_traffic_observations(
        self, chunk_size: int = 1000
    ) -> Iterator[List[TrafficObservation]]:
        """
        Streams Parquet batches chunk-by-chunk using pyarrow or pandas.
        """
        if not self._parquet_path.exists():
            return

        try:
            import pyarrow.parquet as pq
            parquet_file = pq.ParquetFile(self._parquet_path)
            for batch in parquet_file.iter_batches(batch_size=chunk_size):
                df_batch = batch.to_pandas()
                chunk: List[TrafficObservation] = []
                for _, row in df_batch.iterrows():
                    obs = self._normalize_record(row.to_dict())
                    self._unique_sensors.add(obs.sensor_id)
                    self._latest_cache[obs.sensor_id] = obs.to_traffic_condition()
                    chunk.append(obs)
                yield chunk
        except Exception:
            # Fallback to pandas
            import pandas as pd
            df = pd.read_parquet(self._parquet_path)
            total = len(df)
            for i in range(0, total, chunk_size):
                df_slice = df.iloc[i : i + chunk_size]
                chunk = []
                for _, row in df_slice.iterrows():
                    obs = self._normalize_record(row.to_dict())
                    self._unique_sensors.add(obs.sensor_id)
                    self._latest_cache[obs.sensor_id] = obs.to_traffic_condition()
                    chunk.append(obs)
                yield chunk

    def get_latest_traffic(self, road_or_sensor_id: str) -> Optional[TrafficCondition]:
        """Returns the most recent traffic condition for a given sensor or road ID."""
        if road_or_sensor_id in self._latest_cache:
            return self._latest_cache[road_or_sensor_id]

        for chunk in self.stream_traffic_observations(chunk_size=2000):
            for obs in chunk:
                if obs.sensor_id == road_or_sensor_id or obs.road_id == road_or_sensor_id:
                    self._latest_cache[road_or_sensor_id] = obs.to_traffic_condition()
            if road_or_sensor_id in self._latest_cache:
                return self._latest_cache[road_or_sensor_id]

        return None

    def get_metadata(self) -> DatasetMetadata:
        """Returns dataset metadata."""
        size_bytes = self._parquet_path.stat().st_size if self._parquet_path.exists() else 0
        return DatasetMetadata(
            name=self._name,
            format="parquet",
            total_records=0,
            num_sensors=len(self._unique_sensors),
            time_range="Columnar Parquet Record Stream",
            features=["sensor_id", "timestamp", "speed", "flow", "occupancy"],
            metadata={"file_path": str(self._parquet_path), "file_size_bytes": size_bytes},
        )
