"""
Database Exception Hierarchy for AI-SecOps Framework.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class DatabaseError(Exception):
    """Base exception for all database-related errors."""

    def __init__(
        self,
        message: str,
        original_exception: Optional[Exception] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.original_exception = original_exception
        self.details = details or {}


class DatabaseConfigurationError(DatabaseError):
    """Raised when database configuration settings are invalid or missing."""

    pass


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection acquisition or pool creation fails."""

    pass


class RepositoryError(DatabaseError):
    """Raised when data access or query execution fails in repository layer."""

    pass


class AuditEventError(DatabaseError):
    """Raised when an audit event is malformed or invalid."""

    pass
