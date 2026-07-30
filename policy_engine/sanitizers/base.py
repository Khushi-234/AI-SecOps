"""
Abstract Base Interface for Prompt Sanitizers.

Defines the contract for all prompt sanitization strategy implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from policy_engine.context import RiskContext
from policy_engine.models import SanitizationResult


class BaseSanitizer(ABC):
    """
    Abstract base class for all prompt sanitization modules.
    """

    @abstractmethod
    def sanitize(
        self, prompt: str, context: RiskContext | None = None
    ) -> SanitizationResult:
        """
        Sanitizes a prompt string based on regex patterns or findings in RiskContext.

        Args:
            prompt: Original input prompt string.
            context: Optional RiskContext payload containing evidence findings.

        Returns:
            SanitizationResult containing sanitized text and edit tracking records.
        """
        pass
