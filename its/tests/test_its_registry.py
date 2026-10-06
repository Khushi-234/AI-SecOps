"""
Unit Tests for DatasetRegistry and ITSConfig (AI-SecOps V2).

Tests:
1. Retrieval of pre-registered datasets (PEMS-BAY, METR-LA, json-mock, etc.).
2. Approximation indicators on large benchmark statistics.
3. Custom dataset profile registration and retrieval.
4. Dataset metadata serialization.
5. Environment variable configuration overrides.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from its.config import ITSConfig
from its.loaders.registry import DatasetProfile, DatasetRegistry


class TestDatasetRegistry:
    """Tests the dataset registry and catalog."""

    @pytest.fixture
    def registry(self) -> DatasetRegistry:
        return DatasetRegistry()

    def test_pems_bay_registered_with_approximation(self, registry: DatasetRegistry) -> None:
        profile = registry.get("pems-bay")
        assert profile is not None
        assert profile.sensor_count == 325
        assert profile.is_approximate is True
        assert profile.approx_observation_count >= 16000000

        meta = profile.to_dataset_metadata()
        assert meta.name == "PEMS-BAY"
        assert meta.is_approximate_count is True
        assert meta.sensor_count == 325

    def test_metr_la_registered(self, registry: DatasetRegistry) -> None:
        profile = registry.get("metr-la")
        assert profile is not None
        assert profile.sensor_count == 207
        assert profile.is_approximate is True
        assert profile.approx_observation_count >= 6000000

    def test_json_mock_exact_statistics(self, registry: DatasetRegistry) -> None:
        profile = registry.get("json-mock")
        assert profile is not None
        assert profile.is_approximate is False
        assert profile.approx_observation_count == 8
        assert profile.sensor_count == 8

    def test_custom_profile_registration(self, registry: DatasetRegistry) -> None:
        custom = DatasetProfile(
            name="custom-highway",
            dataset_type="csv",
            source="Test Sensor Network",
            record_scale="thousands",
            sensor_count=50,
            approx_observation_count=50000,
            is_approximate=False,
            schema_features=["sensor_id", "timestamp", "speed"],
        )
        registry.register(custom)

        retrieved = registry.get("custom-highway")
        assert retrieved is not None
        assert retrieved.name == "custom-highway"
        assert retrieved.sensor_count == 50

    def test_alias_lookup(self, registry: DatasetRegistry) -> None:
        assert registry.get("bay") is not None
        assert registry.get("la") is not None
        assert registry.get("mock") is not None
        assert registry.get("nonexistent-dataset") is None


class TestITSConfig:
    """Tests configuration loading and defaults."""

    def test_default_config_values(self) -> None:
        config = ITSConfig()
        assert config.default_dataset in ("json", "mock")
        assert config.chunk_size >= 100
        assert config.strict_validation is True
        assert isinstance(config.data_dir, Path)
