"""
ITSDataLoaderFactory — Factory pattern for instantiating transportation dataset loaders.

Supports instant switching between:
- Mock JSON datasets (roads.json, traffic.json, incidents.json)
- Large CSV streaming files
- Parquet columnar files (including NYC TLC)
- Caltrans PEMS-BAY and Los Angeles METR-LA adapters
- DatasetRegistry profiles
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union

from its.config import ITSConfig
from its.loaders.base_loader import BaseITSDataLoader
from its.loaders.csv_loader import CSVTrafficDataLoader
from its.loaders.json_loader import JSONMockDataLoader
from its.loaders.parquet_loader import ParquetTrafficDataLoader
from its.loaders.pems_adapter import PEMSAdapter
from its.loaders.registry import DatasetProfile, DatasetRegistry


class ITSDataLoaderFactory:
    """
    Factory for instantiating ITS data loaders and adapters.
    """

    @staticmethod
    def create_loader(
        source_type: Optional[str] = None,
        config: Optional[ITSConfig] = None,
        **kwargs: Any,
    ) -> BaseITSDataLoader:
        """
        Creates an ITS data loader based on dataset type.

        Args:
            source_type: One of 'json', 'csv', 'parquet', 'pems-bay', 'metr-la', 'pems', 'nyc-tlc'.
                         Defaults to ITSConfig.default_dataset if None.
            config: Optional ITSConfig instance.
            **kwargs: Arguments forwarded to the specific loader class.

        Returns:
            An instance of BaseITSDataLoader.
        """
        cfg = config or ITSConfig()
        st = (source_type or cfg.default_dataset).lower().strip().replace("_", "-")

        if st in ("json", "mock", "json-mock"):
            roads_p = kwargs.get("roads_path") or str(cfg.data_dir / "roads.json")
            traffic_p = kwargs.get("traffic_path") or str(cfg.data_dir / "traffic.json")
            incidents_p = kwargs.get("incidents_path") or str(cfg.data_dir / "incidents.json")
            return JSONMockDataLoader(
                roads_path=roads_p,
                traffic_path=traffic_p,
                incidents_path=incidents_p,
            )
        elif st == "csv":
            csv_path = kwargs.get("csv_path") or cfg.custom_csv_path
            if not csv_path:
                raise ValueError("CSV loader requires 'csv_path' argument or ITS_CSV_PATH env variable.")
            return CSVTrafficDataLoader(csv_path=csv_path, **kwargs)
        elif st in ("parquet", "pq"):
            pq_path = kwargs.get("parquet_path") or cfg.custom_parquet_path
            if not pq_path:
                raise ValueError("Parquet loader requires 'parquet_path' argument or ITS_PARQUET_PATH env variable.")
            return ParquetTrafficDataLoader(parquet_path=pq_path, **kwargs)
        elif st in ("pems-bay", "pemsbay"):
            data_file = kwargs.get("data_file") or cfg.pems_bay_path
            return PEMSAdapter(dataset_name="PEMS-BAY", data_file=data_file, **kwargs)
        elif st in ("metr-la", "metrla"):
            data_file = kwargs.get("data_file") or cfg.metr_la_path
            return PEMSAdapter(dataset_name="METR-LA", data_file=data_file, **kwargs)
        elif st.startswith("pems"):
            return PEMSAdapter(dataset_name=st.upper(), **kwargs)
        elif st in ("nyc-tlc", "tlc"):
            pq_path = kwargs.get("parquet_path") or cfg.custom_parquet_path
            if not pq_path:
                raise ValueError("NYC TLC loader requires 'parquet_path' argument or ITS_PARQUET_PATH env variable.")
            return ParquetTrafficDataLoader(parquet_path=pq_path, name="NYC TLC Trip Dataset", **kwargs)
        else:
            raise ValueError(
                f"Unknown ITS dataset source type: '{source_type}'. "
                f"Supported: 'json', 'csv', 'parquet', 'pems-bay', 'metr-la', 'pems', 'nyc-tlc'."
            )

    @staticmethod
    def create_from_profile(profile: DatasetProfile, **kwargs: Any) -> BaseITSDataLoader:
        """Creates loader directly from a registered DatasetProfile."""
        return ITSDataLoaderFactory.create_loader(
            source_type=profile.name,
            data_file=profile.file_path,
            **kwargs,
        )

    @staticmethod
    def auto_detect(file_path: Union[str, Path], **kwargs: Any) -> BaseITSDataLoader:
        """
        Auto-detects appropriate loader from file extension and path naming.
        """
        p = Path(file_path)
        ext = p.suffix.lower()

        if "pems" in p.name.lower() or "bay" in p.name.lower():
            return PEMSAdapter(dataset_name="PEMS-BAY", data_file=p, **kwargs)
        elif "metr" in p.name.lower() or "la" in p.name.lower():
            return PEMSAdapter(dataset_name="METR-LA", data_file=p, **kwargs)
        elif ext == ".json":
            return JSONMockDataLoader(traffic_path=str(p), **kwargs)
        elif ext == ".csv":
            return CSVTrafficDataLoader(csv_path=p, **kwargs)
        elif ext in (".parquet", ".pq"):
            return ParquetTrafficDataLoader(parquet_path=p, **kwargs)
        else:
            return CSVTrafficDataLoader(csv_path=p, **kwargs)
