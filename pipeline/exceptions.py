"""
Typed Exception hierarchy for AI-SecOps Framework pipeline execution.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class PipelineError(Exception):
    """Base exception for all pipeline-related errors."""

    def __init__(
        self,
        message: str,
        stage: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.request_id = request_id
        self.details = details or {}


class PipelineConfigurationError(PipelineError):
    """Raised when pipeline or module dependency injection configuration is invalid."""

    pass


class PipelineExecutionError(PipelineError):
    """Raised when an error occurs during pipeline stage execution."""

    pass


class FailSecurePipelineError(PipelineError):
    """Raised when fail-secure boundary intercepts a critical exception."""

    def __init__(
        self,
        message: str,
        original_exception: Optional[Exception] = None,
        stage: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, stage=stage, request_id=request_id, details=details)
        self.original_exception = original_exception


class PipelineBlockException(PipelineError):
    """Internal signal exception when a pipeline stage blocks execution."""

    def __init__(
        self,
        message: str,
        blocked_by: str,
        stage: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, stage=stage, request_id=request_id, details=details)
        self.blocked_by = blocked_by
