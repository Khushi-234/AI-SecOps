"""
Secret & Credential Prompt Sanitizer Implementation.

Masks sensitive secrets, API keys, tokens, and credentials from prompt text.
"""

from __future__ import annotations

import re
import time

from policy_engine.context import RiskContext
from policy_engine.enums import SanitizationType
from policy_engine.models import SanitizationEdit, SanitizationResult
from policy_engine.sanitizers.base import BaseSanitizer
from policy_engine.utils import apply_sanitization_edits

class SecretSanitizer(BaseSanitizer):
    """
    Masks credentials, tokens, and API keys in prompt text.
    """

    AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    GENERIC_API_KEY_REGEX = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
    )
    BEARER_TOKEN_REGEX = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b")
    JWT_REGEX = re.compile(
        r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )

    def __init__(self, placeholder: str = "[REDACTED_SECRET]") -> None:
        self._placeholder = placeholder


    def _add_edit(
        self,
        edits: list[SanitizationEdit],
        edit_id: str,
        original: str,
        start: int,
        end: int,
        replacement: str,
    ) -> None:
        """
        Creates and appends SanitizationEdit while avoiding overlaps.
        """

        # Avoid duplicate overlapping edits
        if any(e.start_char <= start < e.end_char for e in edits):
            return

        edits.append(
            SanitizationEdit(
                edit_id=edit_id,
                sanitization_type=SanitizationType.SECRET_MASKING,
                original_text=original,
                replacement_text=replacement,
                start_char=start,
                end_char=end,
            )
        )

    def sanitize(
        self,
        prompt: str,
        context: RiskContext | None = None
    ) -> SanitizationResult:

        start_time = time.perf_counter()

        edits: list[SanitizationEdit] = []
        edit_counter = 1

        # Common secret patterns
        secret_patterns = [
            (
                "aws",
                self.AWS_KEY_REGEX,
                self._placeholder
            ),
            (
                "jwt",
                self.JWT_REGEX,
                self._placeholder
            ),
            (
                "bearer",
                self.BEARER_TOKEN_REGEX,
                f"Bearer {self._placeholder}"
            ),
        ]

        # Handle AWS, JWT, Bearer tokens
        for secret_type, regex, replacement in secret_patterns:

            for match in regex.finditer(prompt):

                self._add_edit(
                    edits=edits,
                    edit_id=f"secret_{secret_type}_{edit_counter}",
                    original=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    replacement=replacement,
                )

                edit_counter += 1

        # Handle API key=value format separately
        for match in self.GENERIC_API_KEY_REGEX.finditer(prompt):
            key_name = match.group(1)

            self._add_edit(
                edits=edits,
                edit_id=f"secret_api_{edit_counter}",
                original=match.group(0),
                start=match.start(),
                end=match.end(),
                replacement=f"{key_name}: {self._placeholder}",
            )

            edit_counter += 1

        # RiskContext evidence based sanitization
        if context and context.evidence:
            for item in context.evidence:
                finding_type = str(getattr(item, "finding_type", "")).lower()
                metadata = getattr(item, "metadata", {}) or {}
                matched = (getattr(item, "matched_text", None)or metadata.get("matched_text"))
                if ("secret" in finding_type or "credential" in finding_type or "key" in finding_type):
                    if isinstance(matched, str) and matched in prompt:
                        position = 0

                        while True:

                            position = prompt.find(matched,position)
                            if position == -1:
                                break

                            self._add_edit(
                                edits=edits,
                                edit_id=f"secret_evidence_{edit_counter}",
                                original=matched,
                                start=position,
                                end=position + len(matched),
                                replacement=self._placeholder,
                            )

                            edit_counter += 1
                            position += len(matched)

        sanitized_prompt = apply_sanitization_edits(prompt,edits)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SanitizationResult(
            sanitized_prompt=sanitized_prompt,
            edits=tuple(edits),
            processing_time_ms=elapsed_ms,
        )