# models.py
"""Data models for the Input Validator module.

Defines the structures used to convey validation outcomes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Any, Dict, Optional


@dataclass(frozen=True)
class ValidationResult:
    """Result of a single validator.

    Attributes:
        validator_name: Name of the validator class.
        is_valid: Whether the validator passed.
        error_message: Human‑readable explanation if validation failed.
        execution_time_ms: Execution duration in milliseconds.
        timestamp: Timestamp of when validation completed.
        metadata: Key-value metadata about the check execution.
    """
    validator_name: str
    is_valid: bool
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    # @property
    # def success(self) -> bool:
    #     """Backward-compatible alias for is_valid."""
    #     return self.is_valid

    # @property
    # def message(self) -> str:
    #     """Backward-compatible alias for error_message."""
    #     return self.error_message or ""

    # @property
    # def details(self) -> Dict[str, Any]:
    #     """Backward-compatible alias for metadata."""
    #     return self.metadata


@dataclass(frozen=True)
class ConversationMessage:
    """Represents a single message inside a conversation history.

    Attributes:
        role: The role of the speaker (e.g., 'system', 'user', 'assistant').
        content: The text payload of the message.
    """
    role: str
    content: str


@dataclass(frozen=True)
class ConversationPayload:
    """Represents the complete input request including current prompt and history.

    Attributes:
        user: Current user prompt or query.
        history: List of preceding conversation messages.
    """
    user: str
    history: List[ConversationMessage] = field(default_factory=list)


@dataclass(frozen=True)
class InputValidationResponse:
    """Aggregated response from the whole validation pipeline.

    Attributes:
        is_valid: Overall success – ``True`` only if *all* validators succeeded.
        results: List of :class:`ValidationResult` objects in execution order.
        execution_time_ms: Total execution duration in milliseconds.
        metadata: Aggregated telemetry metadata.
    """
    is_valid: bool
    results: List[ValidationResult]
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # @property
    # def success(self) -> bool:
    #     """Backward-compatible alias for is_valid."""
    #     return self.is_valid

