"""
AuditEvent Data Model & Enums for AI-SecOps Framework PostgreSQL Persistence.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class AuditEventCategory(str, Enum):
    """Event category constants across AI-SecOps pipeline stages."""

    INPUT_VALIDATION = "INPUT_VALIDATION"
    PROMPT_FIREWALL = "PROMPT_FIREWALL"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    POLICY_DECISION = "POLICY_DECISION"
    PROMPT_HARDENING = "PROMPT_HARDENING"
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"
    OUTPUT_GUARD = "OUTPUT_GUARD"
    PIPELINE_EVENT = "PIPELINE_EVENT"
    ERROR = "ERROR"
    FAIL_SECURE = "FAIL_SECURE"


class EventSeverity(str, Enum):
    """Severity classification level of audit event."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventAction(str, Enum):
    """Action taken by the emitting security module."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"
    HARDEN = "HARDEN"
    SANITIZE = "SANITIZE"
    EXECUTE = "EXECUTE"
    FAIL_SECURE = "FAIL_SECURE"
    UNKNOWN = "UNKNOWN"


class EventStatus(str, Enum):
    """Execution status outcome of the logged event."""

    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"
    ERROR = "ERROR"
    FAIL_SECURE = "FAIL_SECURE"


# Sensitive Key Regex Patterns for secret scrubbing
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|auth|bearer|credentials|private[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_VAL_PATTERN = re.compile(
    r"(?:gsk_[A-Za-z0-9_]{20,}|bearer\s+[A-Za-z0-9._~+/-]+=*)",
    re.IGNORECASE,
)


def sanitize_payload(obj: Any) -> Any:
    """
    Recursively scrubs sensitive keys, tokens, passwords, and API keys from metadata dicts or lists.
    """
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if isinstance(k, str) and SENSITIVE_KEY_PATTERN.search(k):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_payload(v)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    elif isinstance(obj, str):
        if SENSITIVE_VAL_PATTERN.search(obj):
            return SENSITIVE_VAL_PATTERN.sub("[REDACTED]", obj)
        return obj
    return obj


@dataclass(slots=True, frozen=True)
class AuditEvent:
    """
    Structured Audit Event data transfer model for persistence in PostgreSQL.

    Attributes:
        event_id: Unique audit event correlation identifier.
        request_id: Core request correlation identifier.
        trace_id: Distributed trace identifier (defaults to request_id).
        component: Pipeline component name emitting the event.
        event_type: Category identifier of event (AuditEventCategory or string).
        severity: Event severity level (EventSeverity or string).
        action: Module action decision (EventAction or string).
        status: Outcome status (EventStatus or string).
        message: Human-readable log summary message.
        metadata: Key-value dictionary of contextual findings and telemetry.
        timestamp: Timezone-aware UTC timestamp when event occurred.
    """

    request_id: str
    component: str
    event_type: AuditEventCategory | str
    message: str
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}")
    trace_id: str = ""
    severity: EventSeverity | str = EventSeverity.INFO
    action: EventAction | str = EventAction.ALLOW
    status: EventStatus | str = EventStatus.SUCCESS
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validates fields, defaults trace_id, normalizes string enums, and scrubs secrets."""
        if not self.request_id:
            raise ValueError("AuditEvent request_id must not be empty.")
        if not self.component:
            raise ValueError("AuditEvent component must not be empty.")

        # Default trace_id to request_id if empty
        if not self.trace_id:
            object.__setattr__(self, "trace_id", self.request_id)

        # Normalize enums to string representation
        evt_type_val = (
            self.event_type.value if isinstance(self.event_type, Enum) else self.event_type
        )
        sev_val = (
            self.severity.value if isinstance(self.severity, Enum) else self.severity
        )
        act_val = (
            self.action.value if isinstance(self.action, Enum) else self.action
        )
        stat_val = (
            self.status.value if isinstance(self.status, Enum) else self.status
        )

        object.__setattr__(self, "event_type", evt_type_val.upper())
        object.__setattr__(self, "severity", sev_val.upper())
        object.__setattr__(self, "action", act_val.upper())
        object.__setattr__(self, "status", stat_val.upper())

        # Redact secrets from message and metadata
        clean_msg = sanitize_payload(self.message)
        clean_meta = sanitize_payload(dict(self.metadata))

        object.__setattr__(self, "message", str(clean_msg))
        object.__setattr__(self, "metadata", clean_meta)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes AuditEvent instance to dictionary."""
        return {
            "event_id": self.event_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp.isoformat(),
            "component": self.component,
            "event_type": self.event_type,
            "severity": self.severity,
            "action": self.action,
            "status": self.status,
            "message": self.message,
            "metadata": dict(self.metadata),
        }
