"""
AI-SecOps Framework Database & Audit Logging Module.
"""

from database.audit.audit_logger import DatabaseAuditLogger
from database.config import DatabaseConfig
from database.connection import PostgresConnectionManager
from database.exceptions import (
    AuditEventError,
    DatabaseConfigurationError,
    DatabaseConnectionError,
    DatabaseError,
    RepositoryError,
)
from database.migrations.migrate import run_migrations
from database.models.audit_event import (
    AuditEvent,
    AuditEventCategory,
    EventAction,
    EventSeverity,
    EventStatus,
)
from database.repositories.audit_repository import AuditRepository

__all__ = [
    "DatabaseConfig",
    "PostgresConnectionManager",
    "AuditEvent",
    "AuditEventCategory",
    "EventSeverity",
    "EventAction",
    "EventStatus",
    "AuditRepository",
    "DatabaseAuditLogger",
    "run_migrations",
    "DatabaseError",
    "DatabaseConfigurationError",
    "DatabaseConnectionError",
    "RepositoryError",
    "AuditEventError",
]
