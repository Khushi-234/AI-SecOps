# context.py
"""Validation context used across validators.

The :class:`ValidationContext` carries the input data and any auxiliary
information that validators might need (e.g., pre‑computed resources).
"""

from dataclasses import dataclass
from typing import Any, Dict , List, Optional
from .models import ValidationResult, ConversationPayload, ConversationMessage
from .logger import validator_logger
@dataclass
class ValidationContext:
    """Validates full conversation history alongside the current user prompt."""

    def __init__(
        self,
        max_history_turns: int = 50,
        max_total_chars: int = 20000,
        allowed_roles: Optional[List[str]] = None
    ):
        """Initialize context validation limits.

        Args:
            max_history_turns: Maximum allowed turns in history.
            max_total_chars: Max allowed combined characters in history + prompt.
            allowed_roles: Allowed role identifiers (default: system, user, assistant).
        """
        self.max_history_turns = max_history_turns
        self.max_total_chars = max_total_chars
        self.allowed_roles = set(allowed_roles or ["system", "user", "assistant"])

    def validate(self, payload: ConversationPayload) -> ValidationResult:
        """Runs conversation-level assertions across payload and history.

        Args:
            payload: ConversationPayload containing user prompt and history.

        Returns:
            ValidationResult summarizing context validity.
        """
        validator_name = self.__class__.__name__

        # 1. Validate prompt presence
        if not payload.user or not payload.user.strip():
            validator_logger.warning("Context validation failed: empty current user prompt.")
            return ValidationResult(
                is_valid=False,
                validator_name=validator_name,
                error_message="Current user prompt cannot be empty.",
                metadata={"reason": "empty_user_prompt"}
            )
        
        # 2. Check history length
        history_len = len(payload.history)
        if history_len > self.max_history_turns:
            validator_logger.warning(
                f"Context validation failed: turn count {history_len} exceeds limit {self.max_history_turns}."
            )
            return ValidationResult(
                is_valid=False,
                validator_name=validator_name,
                error_message=f"Conversation history exceeds limit of {self.max_history_turns} turns.",
                metadata={"turn_count": history_len, "max_turns": self.max_history_turns}
            )

        # 3. Role and length verification
        total_chars = len(payload.user)
        for idx, msg in enumerate(payload.history):
            if msg.role not in self.allowed_roles:
                validator_logger.warning(
                    f"Context validation failed: invalid role '{msg.role}' at index {idx}."
                )
                return ValidationResult(
                    is_valid=False,
                    validator_name=validator_name,
                    error_message=f"Invalid role '{msg.role}' at history index {idx}.",
                    metadata={"index": idx, "invalid_role": msg.role}
                )
            
            total_chars += len(msg.content or "")

        # 4. Total character count sanity
        if total_chars > self.max_total_chars:
            validator_logger.warning(
                f"Context validation failed: combined payload size {total_chars} exceeds max {self.max_total_chars}."
            )
            return ValidationResult(
                is_valid=False,
                validator_name=validator_name,
                error_message=f"Total context size exceeds maximum allowance of {self.max_total_chars} characters.",
                metadata={"total_chars": total_chars, "max_chars": self.max_total_chars}
            )

        validator_logger.info("Context validation passed is_valid=fully.")
        return ValidationResult(
            is_valid=True,
            validator_name=validator_name,
            error_message=None,
            metadata={
                "turn_count": history_len,
                "total_chars": total_chars
            }
        )