"""
Prompt Injection & Control Token Sanitizer Implementation.

Strips delimiter tokens, special control tags, and system override attempts from prompts.
"""

from __future__ import annotations

import re
import time

from policy_engine.context import RiskContext
from policy_engine.enums import SanitizationType
from policy_engine.models import SanitizationEdit, SanitizationResult
from policy_engine.sanitizers.base import BaseSanitizer
from policy_engine.utils import apply_sanitization_edits


class InjectionSanitizer(BaseSanitizer):
    """
    Strips dangerous control tokens, ChatML tags, and override delimiters.
    """

    # Delimiters and Injection Control Tokens
    DANGEROUS_TOKENS = [
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        re.compile(r"\[SYSTEM PROMPT\]", re.IGNORECASE),
        re.compile(r"\[INSTRUCTION OVERRIDE\]", re.IGNORECASE),
        re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    ]

    def sanitize(
        self, prompt: str, context: RiskContext | None = None
    ) -> SanitizationResult:
        """
        Strips dangerous tokens from prompt text.
        """
        start_time = time.perf_counter()
        edits: list[SanitizationEdit] = []
        edit_counter = 1

        for regex in self.DANGEROUS_TOKENS:
            for match in regex.finditer(prompt):
                original = match.group(0)
                start, end = match.span()
                edits.append(
                    SanitizationEdit(
                        edit_id=f"injection_strip_{edit_counter}",
                        sanitization_type=SanitizationType.INJECTION_STRIPPING,
                        original_text=original,
                        replacement_text="",
                        start_char=start,
                        end_char=end,
                    )
                )
                edit_counter += 1

        sanitized_prompt = apply_sanitization_edits(prompt, edits)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SanitizationResult(
            sanitized_prompt=sanitized_prompt,
            edits=tuple(edits),
            processing_time_ms=elapsed_ms,
        )
