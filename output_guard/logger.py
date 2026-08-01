"""
Structured logging module for Output Guard.

Provides standard logging helpers matching the AI-SecOps framework logging design.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

from output_guard.enums import OutputAction
from output_guard.models import OutputFinding, OutputSanitizationResult

LOGGER_NAME = "output_guard.audit"


def get_output_guard_logger() -> logging.Logger:
    """Returns the dedicated Output Guard audit logger."""
    return logging.getLogger(LOGGER_NAME)


def log_detection(finding: OutputFinding) -> None:
    """Logs individual detector security finding."""
    logger = get_output_guard_logger()
    logger.info(
        "[OutputGuard Detection] Detector: %s | Type: %s | Severity: %s | Confidence: %.2f | Matches: %d",
        finding.detector_name,
        finding.finding_type,
        finding.severity,
        finding.confidence,
        len(finding.matches),
    )


def log_pipeline(pipeline_name: str, active_count: int, stage: str = "START") -> None:
    """Logs sanitization pipeline lifecycle event."""
    logger = get_output_guard_logger()
    logger.info(
        "[OutputGuard Pipeline] Stage: %s | Pipeline: %s | Active Sanitizers: %d",
        stage,
        pipeline_name,
        active_count,
    )


def log_sanitization(
    sanitizer_name: str,
    modified: bool,
    replacements_count: int,
    execution_time_ms: float,
) -> None:
    """Logs individual sanitizer execution metrics."""
    logger = get_output_guard_logger()
    logger.info(
        "[OutputGuard Sanitization] Sanitizer: %s | Modified: %s | Replacements: %d | Time: %.2fms",
        sanitizer_name,
        modified,
        replacements_count,
        execution_time_ms,
    )


def log_final_result(result: OutputSanitizationResult) -> None:
    """Logs final Composite Output Guard result payload."""
    logger = get_output_guard_logger()
    logger.info(
        "[OutputGuard Result] Action: %s | Modified: %s | Applied Sanitizers: %s | Detected Issues: %d | Total Time: %.2fms",
        result.action_taken,
        result.modified,
        result.applied_sanitizers,
        len(result.detected_issues),
        result.execution_time_ms,
    )


__all__ = [
    "LOGGER_NAME",
    "get_output_guard_logger",
    "log_detection",
    "log_pipeline",
    "log_sanitization",
    "log_final_result",
]
