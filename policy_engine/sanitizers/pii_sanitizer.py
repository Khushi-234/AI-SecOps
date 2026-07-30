"""
PII Prompt Sanitizer Implementation.

Redacts Personally Identifiable Information (PII) such as emails, phone numbers,
SSNs, and IP addresses from prompt text.
"""

from __future__ import annotations

import re
import time
from typing import Sequence

from policy_engine.context import RiskContext
from policy_engine.enums import SanitizationType
from policy_engine.models import SanitizationEdit, SanitizationResult
from policy_engine.sanitizers.base import BaseSanitizer
from policy_engine.utils import apply_sanitization_edits


class PIISanitizer(BaseSanitizer):
    """
    Sanitizes PII data from prompt text using regex patterns and RiskContext evidence.
    """

    # Standard Regex Patterns for Common PII
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE_REGEX = re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )
    SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    IPV4_REGEX = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    def __init__(self, placeholder: str = "[REDACTED_PII]") -> None:
        """Initializes PIISanitizer with custom placeholder string."""
        self._placeholder: str = placeholder

    def sanitize(
        self, prompt: str, context: RiskContext | None = None
    ) -> SanitizationResult:
        """
        Redacts PII instances from prompt text.
        """
        start_time = time.perf_counter()
        edits: list[SanitizationEdit] = []
        edit_counter = 1

        # 1. Regex Pattern Matching
        patterns = [
            ("email", self.EMAIL_REGEX),
            ("ssn", self.SSN_REGEX),
            ("phone", self.PHONE_REGEX),
            ("ipv4", self.IPV4_REGEX),
        ]

        for pii_kind, regex in patterns:
            for match in regex.finditer(prompt):
                original = match.group(0)
                start, end = match.span()
                edit_id = f"pii_{pii_kind}_{edit_counter}"
                edit_counter += 1

                edits.append(
                    SanitizationEdit(
                        edit_id=edit_id,
                        sanitization_type=SanitizationType.PII_REDACTION,
                        original_text=original,
                        replacement_text=self._placeholder,
                        start_char=start,
                        end_char=end,
                    )
                )

        # 2. RiskContext evidence matching (if evidence includes specific matched_text)
        if context and context.evidence:
            for item in context.evidence:
                finding_type = str(getattr(item, "finding_type", "")).lower()
                source_mod = str(getattr(item, "source_module", "")).lower()
                meta = getattr(item, "metadata", {}) or {}
                matched = (
                    getattr(item, "matched_text", None)
                    or meta.get("matched_text")
                    or getattr(item, "evidence_id", None)
                )

                if "pii" in finding_type or "pii" in source_mod:
                    if matched and isinstance(matched, str) and matched in prompt:
                        # Find all occurrences not already captured
                        idx = 0
                        while True:
                            pos = prompt.find(matched, idx)
                            if pos == -1:
                                break
                            start, end = pos, pos + len(matched)
                            # Check overlaps
                            if not any(e.start_char == start for e in edits):
                                edit_id = f"pii_evidence_{edit_counter}"
                                edit_counter += 1
                                edits.append(
                                    SanitizationEdit(
                                        edit_id=edit_id,
                                        sanitization_type=SanitizationType.PII_REDACTION,
                                        original_text=matched,
                                        replacement_text=self._placeholder,
                                        start_char=start,
                                        end_char=end,
                                    )
                                )
                            idx = pos + len(matched)

        sanitized_prompt = apply_sanitization_edits(prompt, edits)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SanitizationResult(
            sanitized_prompt=sanitized_prompt,
            edits=tuple(edits),
            processing_time_ms=elapsed_ms,
        )
