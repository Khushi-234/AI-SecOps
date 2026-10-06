"""
StreamingDataValidator — Memory-Efficient Streaming Validation for Transportation Datasets.

Validates large-scale streaming observations chunk-by-chunk without loading or
duplicating datasets in RAM:
- Required sensor/road identifiers
- Timestamp syntax and formatting
- Non-negative speed and physical bound checks (0 <= speed <= 250 km/h)
- Sensor occupancy bounds (0.0 <= occupancy <= 1.0)
- Physical traffic flow bounds (flow >= 0)
- Geographic coordinate sanity (-90 <= lat <= 90, -180 <= lon <= 180)
- Congestion level enum conformity
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, List, Optional, Set

from its.models.its_models import CongestionLevel, TrafficObservation


class DataValidationError(ValueError):
    """Raised when transportation dataset validation encounters an unrecoverable schema violation."""
    pass


@dataclass(slots=True)
class ValidationReport:
    """
    Summary of validation findings for a chunk or dataset stream.
    """

    total_records: int = 0
    valid_records: int = 0
    invalid_records: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.invalid_records == 0

    def add_error(self, message: str) -> None:
        self.invalid_records += 1
        if len(self.errors) < 20:  # Keep first 20 errors as samples
            self.errors.append(message)


class StreamingDataValidator:
    """
    Validates traffic observation chunks in a streaming pipeline with constant memory footprint.
    """

    def __init__(
        self,
        max_speed_kmh: float = 250.0,
        strict_fail_fast: bool = False,
    ) -> None:
        self.max_speed_kmh = max_speed_kmh
        self.strict_fail_fast = strict_fail_fast
        self._iso_date_regex = re.compile(
            r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
        )

    def validate_observation(
        self,
        obs: TrafficObservation,
        seen_keys: Optional[Set[str]] = None,
    ) -> List[str]:
        """
        Validates an individual TrafficObservation.

        Returns:
            List of error strings (empty if valid).
        """
        errors: List[str] = []

        # 1. Identifier checks
        if not obs.sensor_id or not str(obs.sensor_id).strip():
            errors.append("Missing required sensor_id/road_id.")
        elif obs.sensor_id.upper() in ("UNKNOWN", "NULL", "NONE"):
            errors.append(f"Invalid sensor_id: '{obs.sensor_id}'")

        # 2. Timestamp format
        if not obs.timestamp or not str(obs.timestamp).strip():
            errors.append("Missing required timestamp.")
        else:
            ts_str = str(obs.timestamp).strip()
            if not self._iso_date_regex.match(ts_str):
                # Try parsing with datetime
                try:
                    datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    errors.append(f"Malformed timestamp format: '{obs.timestamp}'")

        # 3. Speed bounds
        if obs.speed is None or obs.speed < 0.0:
            errors.append(f"Invalid speed value: {obs.speed} (speed cannot be negative)")
        elif obs.speed > self.max_speed_kmh:
            errors.append(f"Physical anomaly: speed {obs.speed} exceeds max threshold {self.max_speed_kmh} km/h")

        # 4. Flow bounds
        if obs.flow is not None and obs.flow < 0.0:
            errors.append(f"Invalid vehicle flow: {obs.flow} (flow cannot be negative)")

        # 5. Occupancy bounds (standard sensor occupancy is 0.0 - 1.0 or 0 - 100%)
        if obs.occupancy is not None:
            if obs.occupancy < 0.0 or obs.occupancy > 100.0:
                errors.append(f"Invalid sensor occupancy: {obs.occupancy}")

        # 6. Geographic coordinates
        if obs.latitude is not None and not (-90.0 <= obs.latitude <= 90.0):
            errors.append(f"Invalid latitude coordinate: {obs.latitude}")
        if obs.longitude is not None and not (-180.0 <= obs.longitude <= 180.0):
            errors.append(f"Invalid longitude coordinate: {obs.longitude}")

        # 7. Congestion level
        valid_levels = {c.value for c in CongestionLevel}
        if obs.congestion_level and obs.congestion_level.upper() not in valid_levels:
            errors.append(f"Unrecognized congestion level: '{obs.congestion_level}'")

        # 8. Duplicate key detection within tracking window
        if seen_keys is not None:
            unique_key = f"{obs.sensor_id}@{obs.timestamp}"
            if unique_key in seen_keys:
                errors.append(f"Duplicate observation detected for sensor '{obs.sensor_id}' at timestamp '{obs.timestamp}'")
            else:
                seen_keys.add(unique_key)

        return errors

    def validate_chunk(
        self,
        chunk: List[TrafficObservation],
        track_duplicates: bool = True,
    ) -> ValidationReport:
        """
        Validates an entire chunk of TrafficObservation objects.
        """
        report = ValidationReport(total_records=len(chunk))
        seen: Optional[Set[str]] = set() if track_duplicates else None

        for obs in chunk:
            errs = self.validate_observation(obs, seen_keys=seen)
            if errs:
                for e in errs:
                    report.add_error(f"[{obs.sensor_id}] {e}")
                if self.strict_fail_fast:
                    raise DataValidationError(f"Strict validation failure: {errs[0]}")
            else:
                report.valid_records += 1

        return report

    def validate_stream(
        self,
        stream: Iterator[List[TrafficObservation]],
        filter_invalid: bool = True,
    ) -> Iterator[List[TrafficObservation]]:
        """
        Wrapping generator that inspects and filters observations on-the-fly.
        """
        for chunk in stream:
            valid_chunk: List[TrafficObservation] = []
            for obs in chunk:
                errs = self.validate_observation(obs)
                if not errs:
                    valid_chunk.append(obs)
                elif self.strict_fail_fast:
                    raise DataValidationError(f"Strict validation failure: {errs[0]}")
                elif not filter_invalid:
                    valid_chunk.append(obs)
            if valid_chunk:
                yield valid_chunk
