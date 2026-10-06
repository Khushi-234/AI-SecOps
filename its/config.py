"""
ITSConfig — Centralized Configuration for AI-SecOps V2 ITS Domain.

Reads environment variables with sensible development defaults, preventing
hardcoded paths and supporting runtime configuration of dataset types and chunk sizes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _env_path(key: str) -> Optional[Path]:
    val = os.getenv(key)
    return Path(val) if val else None


def _env_int(key: str) -> Optional[int]:
    val = os.getenv(key)
    return int(val) if val else None


@dataclass(slots=True)
class ITSConfig:
    """
    Configuration settings for ITS domain data loaders, adapters, and pipelines.
    """

    default_dataset: str = field(
        default_factory=lambda: os.getenv("ITS_DEFAULT_DATASET", "json").lower().strip()
    )
    chunk_size: int = field(
        default_factory=lambda: int(os.getenv("ITS_CHUNK_SIZE", "1000"))
    )
    data_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("ITS_DATA_DIR", str(Path(__file__).resolve().parent / "data"))
        )
    )
    pems_bay_path: Optional[Path] = field(
        default_factory=lambda: _env_path("ITS_PEMS_BAY_PATH")
    )
    metr_la_path: Optional[Path] = field(
        default_factory=lambda: _env_path("ITS_METR_LA_PATH")
    )
    custom_csv_path: Optional[Path] = field(
        default_factory=lambda: _env_path("ITS_CSV_PATH")
    )
    custom_parquet_path: Optional[Path] = field(
        default_factory=lambda: _env_path("ITS_PARQUET_PATH")
    )
    strict_validation: bool = field(
        default_factory=lambda: os.getenv("ITS_STRICT_VALIDATION", "true").lower()
        in ("1", "true", "yes")
    )
    max_streaming_records: Optional[int] = field(
        default_factory=lambda: _env_int("ITS_MAX_STREAMING_RECORDS")
    )

