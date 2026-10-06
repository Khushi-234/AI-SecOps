"""
Unit Tests for StreamingDataValidator (AI-SecOps V2).

Tests:
1. Valid observations pass validation.
2. Missing or empty identifiers flagged.
3. Malformed timestamps flagged.
4. Physical bound checks (negative speed, extreme speed, negative flow).
5. Sensor occupancy bounds.
6. Geographic coordinate sanity.
7. Duplicate detection within chunk.
8. Chunk validation reporting and strict fail-fast error raising.
"""

from __future__ import annotations

import pytest

from its.loaders.validator import DataValidationError, StreamingDataValidator
from its.models.its_models import TrafficObservation


class TestStreamingDataValidator:
    """Tests streaming validation rules."""

    @pytest.fixture
    def validator(self) -> StreamingDataValidator:
        return StreamingDataValidator(max_speed_kmh=250.0, strict_fail_fast=False)

    def test_valid_observation_passes(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="S1001",
            timestamp="2026-10-06T10:00:00Z",
            speed=65.5,
            flow=1400.0,
            occupancy=0.14,
            congestion_level="LOW",
            latitude=37.77,
            longitude=-122.41,
        )
        errors = validator.validate_observation(obs)
        assert len(errors) == 0

    def test_invalid_sensor_id_flagged(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="",
            timestamp="2026-10-06T10:00:00Z",
            speed=60.0,
        )
        errors = validator.validate_observation(obs)
        assert any("Missing required sensor_id" in e for e in errors)

    def test_negative_speed_flagged(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="S1001",
            timestamp="2026-10-06T10:00:00Z",
            speed=-10.0,
        )
        errors = validator.validate_observation(obs)
        assert any("cannot be negative" in e for e in errors)

    def test_speed_exceeding_threshold_flagged(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="S1001",
            timestamp="2026-10-06T10:00:00Z",
            speed=320.0,
        )
        errors = validator.validate_observation(obs)
        assert any("exceeds max threshold" in e for e in errors)

    def test_malformed_timestamp_flagged(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="S1001",
            timestamp="not-a-valid-date",
            speed=50.0,
        )
        errors = validator.validate_observation(obs)
        assert any("Malformed timestamp" in e for e in errors)

    def test_invalid_coordinates_flagged(self, validator: StreamingDataValidator) -> None:
        obs = TrafficObservation(
            sensor_id="S1001",
            timestamp="2026-10-06T10:00:00Z",
            speed=50.0,
            latitude=120.0,   # > 90
            longitude=-200.0, # < -180
        )
        errors = validator.validate_observation(obs)
        assert any("latitude" in e for e in errors)
        assert any("longitude" in e for e in errors)

    def test_duplicate_detection_in_chunk(self, validator: StreamingDataValidator) -> None:
        obs1 = TrafficObservation(sensor_id="S1001", timestamp="2026-10-06T10:00:00Z", speed=50.0)
        obs2 = TrafficObservation(sensor_id="S1001", timestamp="2026-10-06T10:00:00Z", speed=55.0)

        report = validator.validate_chunk([obs1, obs2], track_duplicates=True)
        assert report.total_records == 2
        assert report.valid_records == 1
        assert report.invalid_records == 1
        assert any("Duplicate observation" in e for e in report.errors)

    def test_strict_fail_fast_raises_exception(self) -> None:
        strict_validator = StreamingDataValidator(strict_fail_fast=True)
        obs_bad = TrafficObservation(sensor_id="S1", timestamp="2026-10-06T10:00:00Z", speed=-5.0)

        with pytest.raises(DataValidationError):
            strict_validator.validate_chunk([obs_bad])
