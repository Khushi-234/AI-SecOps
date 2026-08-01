"""
Redaction templates and placeholder constants for Output Guard.
"""

from __future__ import annotations

from typing import Mapping

REDACTION_TEMPLATES: Mapping[str, str] = {
    "SECRET": "[REDACTED_SECRET]",
    "PII": "[REDACTED_PII]",
    "EMAIL": "[REDACTED_EMAIL]",
    "PHONE": "[REDACTED_PHONE]",
    "IP_ADDRESS": "[REDACTED_IP]",
    "SSN": "[REDACTED_SSN]",
    "CREDIT_CARD": "[REDACTED_CREDIT_CARD]",
    "PROMPT_LEAK": "[SYSTEM_INFORMATION_REMOVED]",
    "TOXIC_CONTENT": "[CONTENT_REMOVED_DUE_TO_SAFETY_POLICY]",
    "POLICY_VIOLATION": "[BLOCKED_POLICY_VIOLATION]",
}

__all__ = ["REDACTION_TEMPLATES"]
