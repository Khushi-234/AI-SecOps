"""
DatasetRegistry — Dynamic Catalog and Metadata Registry for Transportation Datasets.

Maintains formal dataset specifications, geographic coverage metadata,
observation scale approximations, and schema contracts for PEMS-BAY, METR-LA,
Caltrans PeMS, NYC TLC, and mock JSON fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from its.config import ITSConfig
from its.models.its_models import DatasetMetadata


@dataclass(slots=True)
class DatasetProfile:
    """
    Profile definition of a registered transportation dataset.
    """

    name: str
    dataset_type: str
    source: str
    record_scale: str
    sensor_count: int
    approx_observation_count: int
    is_approximate: bool = True
    schema_features: List[str] = field(default_factory=list)
    timestamp_field: str = "timestamp"
    geographic_info: str = ""
    supported_query_fields: List[str] = field(default_factory=list)
    default_chunk_size: int = 1000
    file_path: Optional[Path] = None
    status: str = "available"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dataset_metadata(self) -> DatasetMetadata:
        """Converts profile to a DatasetMetadata instance."""
        return DatasetMetadata(
            name=self.name.upper(),
            format=self.dataset_type,
            source=self.source,
            record_scale=self.record_scale,
            sensor_count=self.sensor_count,
            observation_count=self.approx_observation_count,
            is_approximate_count=self.is_approximate,
            status=self.status,
            time_range=self.metadata.get("time_range", "Variable Telemetry Range"),
            timestamp_field=self.timestamp_field,
            geographic_coverage=self.geographic_info,
            features=list(self.schema_features),
            supported_query_fields=list(self.supported_query_fields),
            metadata={
                "default_chunk_size": self.default_chunk_size,
                "file_path": str(self.file_path) if self.file_path else None,
                **self.metadata,
            },
        )


class DatasetRegistry:
    """
    Central catalog of all registered transportation datasets.
    """

    def __init__(self, config: Optional[ITSConfig] = None) -> None:
        self._config = config or ITSConfig()
        self._profiles: Dict[str, DatasetProfile] = {}
        self._register_default_profiles()

    def _register_default_profiles(self) -> None:
        """Populates standard research datasets."""
        # 1. PEMS-BAY (San Francisco Bay Area)
        self.register(
            DatasetProfile(
                name="pems-bay",
                dataset_type="pems",
                source="Caltrans Performance Measurement System (PeMS) — District 4 (Bay Area)",
                record_scale="millions (~16.9M)",
                sensor_count=325,
                approx_observation_count=16937700,
                is_approximate=True,
                schema_features=[
                    "sensor_id",
                    "timestamp",
                    "speed",
                    "flow",
                    "occupancy",
                    "latitude",
                    "longitude",
                ],
                timestamp_field="timestamp",
                geographic_info="San Francisco Bay Area Highway Network (US-101, I-280, I-880, SR-85)",
                supported_query_fields=["sensor_id", "road_name", "timestamp", "congestion_level"],
                default_chunk_size=self._config.chunk_size,
                file_path=self._config.pems_bay_path,
                metadata={
                    "sampling_interval": "5 minutes",
                    "time_range": "2017-01-01 to 2017-06-30 (Approx. 6 months)",
                    "benchmark_reference": "Li et al., DCRNN (ICLR 2018)",
                },
            )
        )

        # 2. METR-LA (Los Angeles County)
        self.register(
            DatasetProfile(
                name="metr-la",
                dataset_type="pems",
                source="Los Angeles County Metropolitan Transportation Authority (LADOT / PeMS D7)",
                record_scale="millions (~6.5M)",
                sensor_count=207,
                approx_observation_count=6511008,
                is_approximate=True,
                schema_features=[
                    "sensor_id",
                    "timestamp",
                    "speed",
                    "flow",
                    "occupancy",
                    "latitude",
                    "longitude",
                ],
                timestamp_field="timestamp",
                geographic_info="Los Angeles County Highway Network (I-5, I-10, I-110, I-405)",
                supported_query_fields=["sensor_id", "road_name", "timestamp", "congestion_level"],
                default_chunk_size=self._config.chunk_size,
                file_path=self._config.metr_la_path,
                metadata={
                    "sampling_interval": "5 minutes",
                    "time_range": "2012-03-01 to 2012-06-27 (Approx. 4 months)",
                    "benchmark_reference": "Jagadish et al., METR-LA traffic speed dataset",
                },
            )
        )

        # 3. PEMS04 (Caltrans PeMS District 4 San Francisco)
        self.register(
            DatasetProfile(
                name="pems04",
                dataset_type="pems",
                source="Caltrans PeMS District 4 (San Francisco Bay Area Traffic Flow)",
                record_scale="millions (~10.0M)",
                sensor_count=307,
                approx_observation_count=10000000,
                is_approximate=True,
                schema_features=["sensor_id", "timestamp", "flow", "occupancy", "speed"],
                timestamp_field="timestamp",
                geographic_info="San Francisco Bay Area Freeway Corridors",
                supported_query_fields=["sensor_id", "timestamp", "flow", "occupancy"],
                default_chunk_size=self._config.chunk_size,
                metadata={"sampling_interval": "5 minutes", "time_range": "2018-01-01 to 2018-02-28"},
            )
        )

        # 4. NYC TLC (New York City Taxi & Limousine Commission)
        self.register(
            DatasetProfile(
                name="nyc-tlc",
                dataset_type="parquet",
                source="NYC Taxi and Limousine Commission Trip Record Data",
                record_scale="tens of millions (~10M-100M+ per year)",
                sensor_count=263,  # 263 TLC Taxi Zones
                approx_observation_count=50000000,
                is_approximate=True,
                schema_features=[
                    "PULocationID",
                    "DOLocationID",
                    "tpep_pickup_datetime",
                    "tpep_dropoff_datetime",
                    "trip_distance",
                    "passenger_count",
                ],
                timestamp_field="tpep_pickup_datetime",
                geographic_info="New York City (Manhattan, Brooklyn, Queens, Bronx, Staten Island)",
                supported_query_fields=["PULocationID", "DOLocationID", "trip_distance"],
                default_chunk_size=self._config.chunk_size,
                file_path=self._config.custom_parquet_path,
                metadata={"record_type": "trip_level", "format": "Parquet"},
            )
        )

        # 5. Mock JSON Development Dataset
        self.register(
            DatasetProfile(
                name="json-mock",
                dataset_type="json",
                source="Simulated Academic Demonstration Fixtures",
                record_scale="smoke-test (8 roads, 8 traffic records, 5 incidents)",
                sensor_count=8,
                approx_observation_count=8,
                is_approximate=False,
                schema_features=["road_id", "timestamp", "average_speed", "vehicle_count", "congestion_level"],
                timestamp_field="timestamp",
                geographic_info="Ahmedabad Urban Corridors (SG Highway, Ring Road, Ashram Road)",
                supported_query_fields=["road_id", "road_name", "congestion_level"],
                default_chunk_size=self._config.chunk_size,
                file_path=self._config.data_dir / "traffic.json",
                status="available",
                metadata={"purpose": "Local development and smoke testing"},
            )
        )

    def register(self, profile: DatasetProfile) -> None:
        """Registers or overrides a dataset profile."""
        key = profile.name.lower().strip()
        self._profiles[key] = profile

    def get(self, name: str) -> Optional[DatasetProfile]:
        """Retrieves a dataset profile by name or alias."""
        key = name.lower().strip().replace("_", "-")
        if key in self._profiles:
            return self._profiles[key]
        if key in ("json", "mock"):
            return self._profiles.get("json-mock")
        if key in ("bay", "pemsbay"):
            return self._profiles.get("pems-bay")
        if key in ("la", "metrla"):
            return self._profiles.get("metr-la")
        return None

    def list_datasets(self) -> List[DatasetProfile]:
        """Returns all registered dataset profiles."""
        return list(self._profiles.values())

    def get_metadata(self, name: str) -> Optional[DatasetMetadata]:
        """Returns DatasetMetadata for a registered dataset."""
        profile = self.get(name)
        if profile:
            return profile.to_dataset_metadata()
        return None
