"""
Abstract base class interface for Output Guard sanitizers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from output_guard.config import OutputGuardConfig
    from output_guard.enums import SanitizationType
    from output_guard.models import SanitizationResult


class BaseSanitizer(ABC):
    """
    Abstract Base Class that every output sanitizer must implement.
    """

    def __init__(self, config: OutputGuardConfig | None = None) -> None:
        from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG

    @property
    @abstractmethod
    def sanitizer_name(self) -> str:
        """Returns the unique human-readable name of the sanitizer."""
        pass

    @property
    @abstractmethod
    def sanitization_type(self) -> SanitizationType:
        """Returns the sanitization category for this sanitizer."""
        pass

    @abstractmethod
    def sanitize(self, output: str) -> SanitizationResult:
        """
        Analyzes and sanitizes the given LLM output string.

        Args:
            output: The generated LLM response to sanitize.

        Returns:
            SanitizationResult containing modified text, status, and detected issues.
        """
        pass


__all__ = ["BaseSanitizer"]
