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

    # Secret Regex Patterns
    AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    GENERIC_API_KEY_REGEX = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"
    )
    BEARER_TOKEN_REGEX = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b")
    JWT_REGEX = re.compile(
        r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )

    def __init__(self, placeholder: str = "[REDACTED_SECRET]") -> None:
        """Initializes SecretSanitizer with custom placeholder string."""
        self._placeholder: str = placeholder

    def sanitize(
        self, prompt: str, context: RiskContext | None = None
    ) -> SanitizationResult:
        """
        Masks secrets in prompt text.
        """
        start_time = time.perf_counter()
        edits: list[SanitizationEdit] = []
        edit_counter = 1

        # 1. AWS Keys
        for match in self.AWS_KEY_REGEX.finditer(prompt):
            original = match.group(0)
            start, end = match.span()
            edits.append(
                SanitizationEdit(
                    edit_id=f"secret_aws_{edit_counter}",
                    sanitization_type=SanitizationType.SECRET_MASKING,
                    original_text=original,
                    replacement_text=self._placeholder,
                    start_char=start,
                    end_char=end,
                )
            )
            edit_counter += 1

        # 2. JWT Tokens
        for match in self.JWT_REGEX.finditer(prompt):
            original = match.group(0)
            start, end = match.span()
            if not any(e.start_char <= start < e.end_char for e in edits):
                edits.append(
                    SanitizationEdit(
                        edit_id=f"secret_jwt_{edit_counter}",
                        sanitization_type=SanitizationType.SECRET_MASKING,
                        original_text=original,
                        replacement_text=self._placeholder,
                        start_char=start,
                        end_char=end,
                    )
                )
                edit_counter += 1

        # 3. Bearer Tokens
        for match in self.BEARER_TOKEN_REGEX.finditer(prompt):
            original = match.group(0)
            start, end = match.span()
            if not any(e.start_char <= start < e.end_char for e in edits):
                edits.append(
                    SanitizationEdit(
                        edit_id=f"secret_bearer_{edit_counter}",
                        sanitization_type=SanitizationType.SECRET_MASKING,
                        original_text=original,
                        replacement_text=f"Bearer {self._placeholder}",
                        start_char=start,
                        end_char=end,
                    )
                )
                edit_counter += 1

        # 4. Key-Value API Keys
        for match in self.GENERIC_API_KEY_REGEX.finditer(prompt):
            original = match.group(0)
            start, end = match.span()
            if not any(e.start_char <= start < e.end_char for e in edits):
                key_name = match.group(1)
                edits.append(
                    SanitizationEdit(
                        edit_id=f"secret_kv_{edit_counter}",
                        sanitization_type=SanitizationType.SECRET_MASKING,
                        original_text=original,
                        replacement_text=f"{key_name}: {self._placeholder}",
                        start_char=start,
                        end_char=end,
                    )
                )
                edit_counter += 1

        # 5. Check context evidence for specific secret matched_text
        if context and context.evidence:
            for item in context.evidence:
                finding_type = str(getattr(item, "finding_type", "")).lower()
                meta = getattr(item, "metadata", {}) or {}
                matched = getattr(item, "matched_text", None) or meta.get("matched_text")
                if ("secret" in finding_type or "credential" in finding_type or "key" in finding_type) and matched:
                    if isinstance(matched, str) and matched in prompt:
                        pos = 0
                        while True:
                            pos = prompt.find(matched, pos)
                            if pos == -1:
                                break
                            start, end = pos, pos + len(matched)
                            if not any(e.start_char <= start < e.end_char for e in edits):
                                edits.append(
                                    SanitizationEdit(
                                        edit_id=f"secret_evidence_{edit_counter}",
                                        sanitization_type=SanitizationType.SECRET_MASKING,
                                        original_text=matched,
                                        replacement_text=self._placeholder,
                                        start_char=start,
                                        end_char=end,
                                    )
                                )
                                edit_counter += 1
                            pos += len(matched)

        sanitized_prompt = apply_sanitization_edits(prompt, edits)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SanitizationResult(
            sanitized_prompt=sanitized_prompt,
            edits=tuple(edits),
            processing_time_ms=elapsed_ms,
        )
