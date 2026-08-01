"""
Sanitizer for detecting and masking Personally Identifiable Information (PII).
"""

from __future__ import annotations

import re
from typing import Any

from prompt_hardener.enums import SanitizationType
from prompt_hardener.models import SanitizationResult
from prompt_hardener.sanitizers.base import BaseSanitizer


class PiiSanitizer(BaseSanitizer):
    """
    Detects and redacts PII elements such as email addresses, phone numbers,
    Social Security Numbers (SSN), and credit card numbers.
    """

    # Email pattern: Standard email format
    EMAIL_PATTERN = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )

    # Phone pattern: Various US/Intl formats (e.g. +1-555-0199, (555) 123-4567, 555-123-4567)
    PHONE_PATTERN = re.compile(
        r"(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b"
    )

    # SSN pattern: 000-00-0000 format
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # Credit Card pattern: 13 to 16 digits with optional dashes/spaces
    CARD_PATTERN = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    )

    @property
    def sanitizer_type(self) -> SanitizationType:
        return SanitizationType.PII

    def sanitize(self, prompt: str) -> SanitizationResult:
        """
        Scans prompt and redacts detected PII elements.
        """
        if not prompt or not isinstance(prompt, str):
            return SanitizationResult(
                original_text=prompt or "",
                sanitized_text=prompt or "",
                sanitizer_type=self.sanitizer_type,
                modified=False,
                replacements_count=0,
            )

        email_token = self.config.email_mask_token
        phone_token = self.config.phone_mask_token
        mask_token = self.config.pii_mask_token

        sanitized = prompt
        replacements = 0

        # Redact Emails
        emails = self.EMAIL_PATTERN.findall(sanitized)
        if emails:
            replacements += len(emails)
            sanitized = self.EMAIL_PATTERN.sub(email_token, sanitized)

        # Redact SSN
        ssns = self.SSN_PATTERN.findall(sanitized)
        if ssns:
            replacements += len(ssns)
            sanitized = self.SSN_PATTERN.sub(mask_token, sanitized)

        # Redact Credit Cards
        cards = self.CARD_PATTERN.findall(sanitized)
        if cards:
            replacements += len(cards)
            sanitized = self.CARD_PATTERN.sub(mask_token, sanitized)

        # Redact Phone Numbers
        phones = self.PHONE_PATTERN.findall(sanitized)
        if phones:
            replacements += len(phones)
            sanitized = self.PHONE_PATTERN.sub(phone_token, sanitized)

        return SanitizationResult(
            original_text=prompt,
            sanitized_text=sanitized,
            sanitizer_type=self.sanitizer_type,
            modified=(sanitized != prompt),
            replacements_count=replacements,
            metadata={"pii_mask_token": mask_token},
        )


__all__ = ["PiiSanitizer"]
