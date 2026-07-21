# models.py
"""Data models for the Input Validator module.

Defines the structures used to convey validation outcomes.
"""

from dataclasses import dataclass, field
from typing import List, Any, Dict


@dataclass(frozen=True)
class ValidationResult:
    """Result of a single validator.

    Attributes:
        success: Whether the validator passed.
        validator_name: Name of the validator class.
        message: Human‑readable explanation of the result.
        details: Optional dictionary with validator‑specific data.
    """
    success: bool
    validator_name: str
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    
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
        success: Overall success – ``True`` only if *all* validators succeeded.
        results: List of :class:`ValidationResult` objects in execution order.
    """
    success: bool
    results: List[ValidationResult]
