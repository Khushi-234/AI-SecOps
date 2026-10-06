"""
ITS Data Loaders and Adapters Package.

Provides scalable ingestion abstractions supporting mock JSON fixtures,
large streaming CSV/Parquet files, Caltrans PeMS / METR-LA adapters,
streaming validation, and dataset registries.
"""

from its.loaders.base_loader import BaseITSDataLoader
from its.loaders.csv_loader import CSVTrafficDataLoader
from its.loaders.factory import ITSDataLoaderFactory
from its.loaders.json_loader import JSONMockDataLoader
from its.loaders.parquet_loader import ParquetTrafficDataLoader
from its.loaders.pems_adapter import PEMSAdapter
from its.loaders.registry import DatasetProfile, DatasetRegistry
from its.loaders.validator import DataValidationError, StreamingDataValidator, ValidationReport

__all__ = [
    "BaseITSDataLoader",
    "JSONMockDataLoader",
    "CSVTrafficDataLoader",
    "ParquetTrafficDataLoader",
    "PEMSAdapter",
    "ITSDataLoaderFactory",
    "DatasetRegistry",
    "DatasetProfile",
    "StreamingDataValidator",
    "DataValidationError",
    "ValidationReport",
]
