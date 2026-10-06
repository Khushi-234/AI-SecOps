"""
BaseITSDataLoader — Abstract base class and contracts for ITS Data Loaders and Adapters.

Defines the standard interface for loading roads, traffic telemetry observations,
and incident reports from various formats (JSON, CSV, Parquet, HDF5, etc.) while
supporting streaming and chunked processing to scale to millions of observations
without exhausting RAM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional

from its.models.its_models import (
    CongestionLevel,
    DatasetMetadata,
    Incident,
    Road,
    TrafficCondition,
    TrafficObservation,
)


class BaseITSDataLoader(ABC):
    """
    Abstract interface for transportation data ingestion adapters.

    Guarantees:
    - Pure domain-level data transformation only (no security decisions or LLM calls).
    - Scalable streaming/chunked iteration over traffic records.
    - Uniform normalization to Road, TrafficCondition, Incident, and TrafficObservation models.
    """

    @abstractmethod
    def load_roads(self) -> List[Road]:
        """Loads and returns all configured road segments."""
        pass

    @abstractmethod
    def load_incidents(self) -> List[Incident]:
        """Loads and returns all incident records."""
        pass

    @abstractmethod
    def stream_traffic_observations(
        self, chunk_size: int = 1000
    ) -> Iterator[List[TrafficObservation]]:
        """
        Streams traffic telemetry observations in chunks.

        Enables memory-efficient processing of millions of traffic observations
        (such as PEMS-BAY or METR-LA) without reading entire datasets into RAM.
        """
        pass

    @abstractmethod
    def get_latest_traffic(self, road_or_sensor_id: str) -> Optional[TrafficCondition]:
        """Retrieves the most recent traffic condition for a given road or sensor identifier."""
        pass

    @abstractmethod
    def get_metadata(self) -> DatasetMetadata:
        """Returns metadata regarding the dataset source, volume, and schema."""
        pass

    def get_all_traffic(self) -> List[TrafficCondition]:
        """
        Returns a snapshot of current traffic conditions across all monitored segments.
        Default implementation aggregates latest observations from streaming or cache.
        """
        roads = self.load_roads()
        results: List[TrafficCondition] = []
        for road in roads:
            cond = self.get_latest_traffic(road.road_id)
            if cond:
                results.append(cond)
        return results

    @staticmethod
    def calculate_congestion_level(
        speed: float,
        speed_limit: float = 65.0,
        occupancy: Optional[float] = None,
    ) -> CongestionLevel:
        """
        Standardized congestion classification based on speed ratio and/or occupancy.

        - speed < 25% of limit or occupancy > 0.35 -> CRITICAL
        - speed < 50% of limit or occupancy > 0.25 -> HIGH
        - speed < 75% of limit or occupancy > 0.15 -> MEDIUM
        - otherwise -> LOW
        """
        if speed_limit <= 0.0:
            speed_limit = 65.0

        ratio = speed / speed_limit

        if occupancy is not None:
            if occupancy >= 0.35:
                return CongestionLevel.CRITICAL
            if occupancy >= 0.25:
                return CongestionLevel.HIGH
            if occupancy >= 0.15:
                return CongestionLevel.MEDIUM

        if ratio <= 0.25:
            return CongestionLevel.CRITICAL
        if ratio <= 0.50:
            return CongestionLevel.HIGH
        if ratio <= 0.75:
            return CongestionLevel.MEDIUM
        return CongestionLevel.LOW

    def get_network_summary(self) -> Dict[str, Any]:
        """Produces aggregate statistics of the traffic network."""
        all_traffic = self.get_all_traffic()
        roads = self.load_roads()
        incidents = self.load_incidents()
        active_incidents = [i for i in incidents if getattr(i, "status", "").upper() == "ACTIVE"]

        counts = {
            CongestionLevel.LOW.value: 0,
            CongestionLevel.MEDIUM.value: 0,
            CongestionLevel.HIGH.value: 0,
            CongestionLevel.CRITICAL.value: 0,
        }
        speeds: List[float] = []
        for t in all_traffic:
            counts[t.congestion_level] = counts.get(t.congestion_level, 0) + 1
            speeds.append(float(t.average_speed))

        avg_spd = sum(speeds) / len(speeds) if speeds else 0.0

        return {
            "total_roads": len(roads),
            "monitored_segments": len(all_traffic),
            "average_network_speed_kmh": round(avg_spd, 2),
            "active_incidents": len(active_incidents),
            "congestion_breakdown": counts,
        }
