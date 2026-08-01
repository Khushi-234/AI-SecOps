"""
Abstract Base Class for all Prompt Sanitizers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG
from prompt_hardener.enums import SanitizationType
from prompt_hardener.models import SanitizationResult


class BaseSanitizer(ABC):
    """
    Abstract interface for prompt sanitizers.
    Each sanitizer receives a prompt and returns a SanitizationResult DTO.
    """

    def __init__(self, config: HardenerConfig | None = None) -> None:
        self.config = config or DEFAULT_HARDENER_CONFIG

    @property
    @abstractmethod
    def sanitizer_type(self) -> SanitizationType:
        """Returns the category of sanitization performed."""
        pass

    @abstractmethod
    def sanitize(self, prompt: str) -> SanitizationResult:
        """
        Sanitizes the provided prompt string.

        Args:
            prompt: Raw or partially sanitized prompt string.

        Returns:
            SanitizationResult containing the original, sanitized text, modification flags, and metadata.
        """
        pass


__all__ = ["BaseSanitizer"]
