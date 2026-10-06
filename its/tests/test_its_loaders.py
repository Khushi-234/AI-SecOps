"""
Unit Tests for ITS Data Loaders and Adapters (AI-SecOps V2).

Tests:
1. JSON mock dataset loading and chunked streaming.
2. CSV streaming loader with chunked iteration.
3. Parquet columnar streaming loader.
4. PEMS-BAY adapter (~16.9M observations metadata, topology, streaming).
5. METR-LA adapter (~6.5M observations metadata, topology, streaming).
6. ITSDataLoaderFactory creation and auto-detection.
"""

from __future__ import annotations

import csv
import os
import tempfile
from pathlib import Path

import pytest

from its.loaders.base_loader import BaseITSDataLoader
from its.loaders.csv_loader import CSVTrafficDataLoader
from its.loaders.factory import ITSDataLoaderFactory
from its.loaders.json_loader import JSONMockDataLoader
from its.loaders.parquet_loader import ParquetTrafficDataLoader
from its.loaders.pems_adapter import PEMSAdapter
from its.models.its_models import CongestionLevel, TrafficObservation


class TestJSONMockDataLoader:
    """Tests the JSON mock data loader."""

    def test_json_loader_initialization_and_roads(self) -> None:
        loader = JSONMockDataLoader()
        roads = loader.load_roads()
        assert len(roads) >= 8
        road_ids = [r.road_id for r in roads]
        assert "RD-001" in road_ids

    def test_json_loader_traffic_and_incidents(self) -> None:
        loader = JSONMockDataLoader()
        traffic = loader.get_all_traffic()
        incidents = loader.load_incidents()
        assert len(traffic) >= 8
        assert len(incidents) >= 5

    def test_json_loader_chunked_streaming(self) -> None:
        loader = JSONMockDataLoader()
        chunks = list(loader.stream_traffic_observations(chunk_size=3))
        assert len(chunks) >= 3
        # First chunk should have at most 3 items
        assert len(chunks[0]) == 3
        assert isinstance(chunks[0][0], TrafficObservation)

    def test_json_loader_metadata(self) -> None:
        loader = JSONMockDataLoader()
        meta = loader.get_metadata()
        assert meta.format == "json"
        assert meta.num_sensors >= 8


class TestCSVTrafficDataLoader:
    """Tests the streaming CSV traffic data loader."""

    @pytest.fixture
    def sample_csv(self, tmp_path: Path) -> Path:
        csv_file = tmp_path / "traffic_sample.csv"
        rows = [
            ["sensor_id", "timestamp", "speed", "flow", "occupancy", "latitude", "longitude"],
            ["S101", "2026-10-06T10:00:00Z", "62.5", "1200", "0.12", "37.77", "-122.41"],
            ["S102", "2026-10-06T10:00:00Z", "18.0", "1900", "0.38", "37.78", "-122.42"],
            ["S103", "2026-10-06T10:00:00Z", "45.0", "1500", "0.22", "37.79", "-122.43"],
            ["S101", "2026-10-06T10:05:00Z", "60.0", "1250", "0.14", "37.77", "-122.41"],
        ]
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)
        return csv_file

    def test_csv_streaming_chunks(self, sample_csv: Path) -> None:
        loader = CSVTrafficDataLoader(csv_path=sample_csv, default_speed_limit=65.0)
        chunks = list(loader.stream_traffic_observations(chunk_size=2))
        assert len(chunks) == 2
        assert len(chunks[0]) == 2
        assert len(chunks[1]) == 2

    def test_csv_congestion_classification(self, sample_csv: Path) -> None:
        loader = CSVTrafficDataLoader(csv_path=sample_csv, default_speed_limit=65.0)
        # S102 has speed 18.0 and occupancy 0.38 -> should be CRITICAL
        cond = loader.get_latest_traffic("S102")
        assert cond is not None
        assert cond.congestion_level in ("HIGH", "CRITICAL")

    def test_csv_load_roads_fallback(self, sample_csv: Path) -> None:
        loader = CSVTrafficDataLoader(csv_path=sample_csv)
        # Run streaming once to discover sensors
        list(loader.stream_traffic_observations(chunk_size=10))
        roads = loader.load_roads()
        assert len(roads) == 3


class TestParquetTrafficDataLoader:
    """Tests the columnar Parquet data loader."""

    @pytest.fixture
    def sample_parquet(self, tmp_path: Path) -> Path:
        import pandas as pd
        pq_file = tmp_path / "traffic_sample.parquet"
        df = pd.DataFrame({
            "sensor_id": ["P201", "P202", "P203", "P204", "P205"],
            "timestamp": ["2026-10-06T10:00:00Z"] * 5,
            "speed": [65.0, 52.0, 20.0, 10.0, 70.0],
            "flow": [1000, 1400, 2100, 2400, 900],
            "occupancy": [0.08, 0.15, 0.32, 0.42, 0.05],
            "latitude": [34.05, 34.06, 34.07, 34.08, 34.09],
            "longitude": [-118.25, -118.26, -118.27, -118.28, -118.29],
        })
        df.to_parquet(pq_file)
        return pq_file

    def test_parquet_chunked_streaming(self, sample_parquet: Path) -> None:
        loader = ParquetTrafficDataLoader(parquet_path=sample_parquet)
        chunks = list(loader.stream_traffic_observations(chunk_size=2))
        assert len(chunks) == 3
        assert len(chunks[0]) == 2
        assert len(chunks[1]) == 2
        assert len(chunks[2]) == 1

    def test_parquet_lookup(self, sample_parquet: Path) -> None:
        loader = ParquetTrafficDataLoader(parquet_path=sample_parquet)
        cond = loader.get_latest_traffic("P204")
        assert cond is not None
        assert cond.average_speed == 10
        assert cond.congestion_level in ("HIGH", "CRITICAL")


class TestPEMSAdapter:
    """Tests Caltrans PeMS and METR-LA dataset adapters."""

    def test_pems_bay_topology_and_metadata(self) -> None:
        adapter = PEMSAdapter(dataset_name="PEMS-BAY")
        meta = adapter.get_metadata()
        assert meta.name == "PEMS-BAY"
        assert meta.num_sensors == 325
        assert meta.total_records == 16937700
        roads = adapter.load_roads()
        assert len(roads) == 325
        assert "US-101" in roads[0].road_name or "I-280" in roads[0].road_name

    def test_metr_la_topology_and_metadata(self) -> None:
        adapter = PEMSAdapter(dataset_name="METR-LA")
        meta = adapter.get_metadata()
        assert meta.name == "METR-LA"
        assert meta.num_sensors == 207
        assert meta.total_records == 6511008
        roads = adapter.load_roads()
        assert len(roads) == 207

    def test_pems_streaming_chunked_processing(self) -> None:
        adapter = PEMSAdapter(dataset_name="PEMS-BAY", total_observations_limit=2500)
        chunks = list(adapter.stream_traffic_observations(chunk_size=1000))
        assert len(chunks) == 3
        assert len(chunks[0]) == 1000
        assert len(chunks[1]) == 1000
        assert len(chunks[2]) == 500
        assert all(isinstance(obs, TrafficObservation) for obs in chunks[0])

    def test_congestion_level_calculation(self) -> None:
        # High speed, low occupancy -> LOW
        c1 = BaseITSDataLoader.calculate_congestion_level(speed=65.0, speed_limit=65.0, occupancy=0.08)
        assert c1 == CongestionLevel.LOW

        # Low speed -> CRITICAL
        c2 = BaseITSDataLoader.calculate_congestion_level(speed=12.0, speed_limit=65.0, occupancy=0.40)
        assert c2 == CongestionLevel.CRITICAL


class TestITSDataLoaderFactory:
    """Tests the loader factory pattern."""

    def test_create_json_loader(self) -> None:
        loader = ITSDataLoaderFactory.create_loader("json")
        assert isinstance(loader, JSONMockDataLoader)

    def test_create_pems_bay_loader(self) -> None:
        loader = ITSDataLoaderFactory.create_loader("pems-bay")
        assert isinstance(loader, PEMSAdapter)
        assert loader.get_metadata().name == "PEMS-BAY"

    def test_create_metr_la_loader(self) -> None:
        loader = ITSDataLoaderFactory.create_loader("metr-la")
        assert isinstance(loader, PEMSAdapter)
        assert loader.get_metadata().name == "METR-LA"

    def test_auto_detect_extension(self, tmp_path: Path) -> None:
        f_csv = tmp_path / "traffic.csv"
        f_csv.write_text("sensor_id,timestamp,speed\nS1,2026-10-06,60\n")
        loader = ITSDataLoaderFactory.auto_detect(f_csv)
        assert isinstance(loader, CSVTrafficDataLoader)
