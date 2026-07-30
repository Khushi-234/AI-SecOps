"""
Centralized Audit Logger for the Policy Engine.

Provides structured logging and security telemetry output.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("policy_engine")


def get_policy_logger() -> logging.Logger:
    """Returns the dedicated Policy Engine logger instance."""
    return logger


def log_policy_decision(
    request_id: str,
    action: str,
    reason: str,
    risk_score: float,
    rule_triggered: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Logs structured audit telemetry for policy decisions.
    """
    log_msg = (
        f"[PolicyEngine Audit] Request: {request_id} | Action: {action} | "
        f"Score: {risk_score:.2f} | Rule: {rule_triggered} | Reason: {reason}"
    )
    if action == "BLOCK":
        logger.warning(log_msg)
    elif action in ("WARN", "SANITIZE"):
        logger.info(log_msg)
    else:
        logger.debug(log_msg)
