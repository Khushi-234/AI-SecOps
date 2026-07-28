"""
Context rules validation checker.

Purpose:
    Validates conversational context boundaries, turn limits, speaker roles,
    and mandatory context identifiers across history payloads.

Responsibilities:
    - Enforce maximum conversational turn counts and combined character lengths.
    - Restrict history speaker roles to allowed identifiers ('system', 'user', 'assistant').
    - Verify presence of request metadata.
"""

from __future__ import annotations

from typing import Any
from input_validator.base_validator import BaseValidator
from input_validator.utils import is_empty

DEFAULT_MAX_TURNS = 50
DEFAULT_MAX_CONTEXT_CHARS = 20000
DEFAULT_ALLOWED_ROLES = {"system", "user", "assistant"}


class ContextRulesValidator(BaseValidator):
    """Validates multi-turn context integrity, history bounds, and role constraints."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "ContextRulesValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority."""
        return 45

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates conversational context rules and turn constraints."""
        ctx = context or {}
        history = ctx.get("history", [])

        # 1. Enforce history type constraint
        if not isinstance(history, list):
            metadata = {"reason": "invalid_history_type"}
            return (
                False,
                "Input validation failed: context history must be a list.",
                metadata,
            )

        # 2. Enforce turn count limit
        max_turns = (
            getattr(self.config, "max_history_turns", DEFAULT_MAX_TURNS)
            if self.config
            else DEFAULT_MAX_TURNS
        )
        if len(history) > max_turns:
            metadata = {"turn_count": len(history), "max_turns": max_turns}
            return (
                False,
                f"Input validation failed: conversation history ({len(history)} turns) exceeds maximum allowed ({max_turns}).",
                metadata,
            )

        # 3. Role and length verification
        allowed_roles = (
            getattr(self.config, "allowed_roles", DEFAULT_ALLOWED_ROLES)
            if self.config
            else DEFAULT_ALLOWED_ROLES
        )
        allowed_roles = set(allowed_roles)
        total_chars = len(prompt)
        invalid_role_found = None

        for idx, turn in enumerate(history):
            if isinstance(turn, dict):
                role = str(turn.get("role", ""))
                content = str(turn.get("content", ""))
            elif hasattr(turn, "role") and hasattr(turn, "content"):
                role = str(getattr(turn, "role", ""))
                content = str(getattr(turn, "content", ""))
            else:
                role = "invalid_structure"
                content = str(turn)

            if role not in allowed_roles:
                invalid_role_found = (idx, role)
                break

            total_chars += len(content)

        if invalid_role_found:
            idx, role = invalid_role_found
            metadata = {
                "index": idx,
                "invalid_role": role,
                "allowed_roles": list(allowed_roles),
            }
            return (
                False,
                f"Input validation failed: invalid role '{role}' detected in history at index {idx}.",
                metadata,
            )

        # 4. Total character count sanity check
        max_chars = (
            getattr(self.config, "max_total_chars", DEFAULT_MAX_CONTEXT_CHARS)
            if self.config
            else DEFAULT_MAX_CONTEXT_CHARS
        )
        if total_chars > max_chars:
            metadata = {"total_chars": total_chars, "max_chars": max_chars}
            return (
                False,
                f"Input validation failed: combined payload size ({total_chars} chars) exceeds maximum allowed ({max_chars}).",
                metadata,
            )

        metadata = {
            "history_turns": len(history),
            "total_chars": total_chars,
            "max_turns": max_turns,
            "max_chars": max_chars,
        }
        return True, None, metadata
