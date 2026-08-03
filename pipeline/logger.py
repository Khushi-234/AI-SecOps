"""
PipelineLogger for correlation-aware logging and execution telemetry logging.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("ai_secops_pipeline")


class PipelineLogger:
    """
    Context-aware logger wrapper providing structured audit and stage telemetry logs.
    """

    def __init__(self, name: str = "ai_secops_pipeline") -> None:
        self._logger = logging.getLogger(name)

    def info(
        self,
        message: str,
        request_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Logs info level audit event with request_id correlation."""
        ctx_msg = f"[{request_id or 'NO_REQ_ID'}] {message}"
        self._logger.info(ctx_msg, extra=extra)

    def warning(
        self,
        message: str,
        request_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Logs warning level audit event with request_id correlation."""
        ctx_msg = f"[{request_id or 'NO_REQ_ID'}] {message}"
        self._logger.warning(ctx_msg, extra=extra)

    def error(
        self,
        message: str,
        request_id: Optional[str] = None,
        exc_info: bool = False,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Logs error level audit event with request_id correlation and optional traceback."""
        ctx_msg = f"[{request_id or 'NO_REQ_ID'}] {message}"
        self._logger.error(ctx_msg, exc_info=exc_info, extra=extra)

    def log_stage_start(self, stage_name: str, request_id: str) -> None:
        """Logs pipeline stage execution entry."""
        self.info(f"Stage '{stage_name}' started.", request_id=request_id)

    def log_stage_complete(
        self, stage_name: str, request_id: str, elapsed_ms: float
    ) -> None:
        """Logs pipeline stage completion with timing telemetry."""
        self.info(
            f"Stage '{stage_name}' completed in {elapsed_ms:.2f} ms.",
            request_id=request_id,
        )

    def log_stage_block(
        self, stage_name: str, request_id: str, reason: str
    ) -> None:
        """Logs pipeline stage execution block decision."""
        self.warning(
            f"Stage '{stage_name}' BLOCKED request. Reason: {reason}",
            request_id=request_id,
        )
