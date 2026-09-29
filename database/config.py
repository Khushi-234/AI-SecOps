"""
Database Configuration management for AI-SecOps Framework PostgreSQL persistence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any, Dict, Optional

from config.settings import settings
from database.exceptions import DatabaseConfigurationError


@dataclass(slots=True)
class DatabaseConfig:
    """
    Centralized PostgreSQL database configuration.

    Supports initialization via DATABASE_URL or discrete environment parameters.
    Ensures credentials are managed securely without hardcoding or leaking in repr/logs.
    """

    database_url: Optional[str] = None
    host: str = field(
        default_factory=lambda: os.getenv("DB_HOST", settings.DB_HOST)
    )
    port: int = field(
        default_factory=lambda: int(os.getenv("DB_PORT", str(settings.DB_PORT)))
    )
    dbname: str = field(
        default_factory=lambda: os.getenv("DB_NAME", settings.DB_NAME)
    )
    user: str = field(
        default_factory=lambda: os.getenv("DB_USER", settings.DB_USER)
    )
    password: str = field(
        default_factory=lambda: os.getenv("DB_PASSWORD", settings.DB_PASSWORD)
    )
    sslmode: str = field(
        default_factory=lambda: os.getenv("DB_SSLMODE", settings.DB_SSLMODE)
    )
    min_connections: int = field(
        default_factory=lambda: int(os.getenv("DB_POOL_MIN", str(settings.DB_POOL_MIN)))
    )
    max_connections: int = field(
        default_factory=lambda: int(os.getenv("DB_POOL_MAX", str(settings.DB_POOL_MAX)))
    )
    connect_timeout: int = field(
        default_factory=lambda: int(os.getenv("DB_CONNECT_TIMEOUT", str(settings.DB_CONNECT_TIMEOUT)))
    )
    fail_secure_on_db_error: bool = field(
        default_factory=lambda: os.getenv("FAIL_SECURE_ON_DB_ERROR", "false").lower() in ("true", "1", "yes")
    )

    def __post_init__(self) -> None:
        """Parses DATABASE_URL if provided, or validates discrete credentials."""
        target_url = self.database_url or os.getenv("DATABASE_URL")
        if target_url and target_url.startswith("postgresql://") and not self.database_url:
            # Only parse env DATABASE_URL if user didn't specify custom host/port/dbname in init
            pass
        elif self.database_url and self.database_url.startswith("postgresql://"):
            try:
                parsed = urlparse(self.database_url)
                if parsed.hostname:
                    self.host = parsed.hostname
                if parsed.port:
                    self.port = parsed.port
                if parsed.username:
                    self.user = parsed.username
                if parsed.password:
                    self.password = parsed.password
                if parsed.path and len(parsed.path) > 1:
                    self.dbname = parsed.path.lstrip("/")
            except Exception as exc:
                raise DatabaseConfigurationError(
                    f"Failed to parse DATABASE_URL: {exc}", original_exception=exc
                ) from exc

        if not self.dbname:
            raise DatabaseConfigurationError("Database name (dbname) cannot be empty.")
        if not self.host:
            raise DatabaseConfigurationError("Database host cannot be empty.")
        if self.port <= 0 or self.port > 65535:
            raise DatabaseConfigurationError(f"Invalid database port: {self.port}")
        if self.min_connections < 1:
            raise DatabaseConfigurationError("min_connections must be >= 1.")
        if self.max_connections < self.min_connections:
            raise DatabaseConfigurationError("max_connections must be >= min_connections.")

    def get_dsn(self) -> str:
        """Returns PostgreSQL connection DSN string for psycopg2."""
        dsn_parts = [
            f"dbname={self.dbname}",
            f"user={self.user}",
            f"password={self.password}",
            f"host={self.host}",
            f"port={self.port}",
            f"connect_timeout={self.connect_timeout}",
        ]
        if self.sslmode:
            dsn_parts.append(f"sslmode={self.sslmode}")
        return " ".join(dsn_parts)

    def get_connection_dict(self) -> Dict[str, Any]:
        """Returns dictionary of connection parameters."""
        return {
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
            "host": self.host,
            "port": self.port,
            "connect_timeout": self.connect_timeout,
            "sslmode": self.sslmode,
        }

    def safe_repr(self) -> str:
        """Returns a string representation with password masked to prevent credential leaks."""
        masked_pwd = "****" if self.password else ""
        return (
            f"DatabaseConfig(host='{self.host}', port={self.port}, "
            f"dbname='{self.dbname}', user='{self.user}', password='{masked_pwd}', "
            f"sslmode='{self.sslmode}', min_connections={self.min_connections}, "
            f"max_connections={self.max_connections})"
        )
