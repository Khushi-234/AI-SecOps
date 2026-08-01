"""
Abstract Base Class for Prompt Injectors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG


class BaseInjector(ABC):
    """
    Abstract interface for prompt injectors.
    Injectors decorate prompts with system defenses, security constraints, or defensive instructions.
    """

    def __init__(self, config: HardenerConfig | None = None) -> None:
        self.config = config or DEFAULT_HARDENER_CONFIG

    @property
    @abstractmethod
    def injector_id(self) -> str:
        """Unique identifier for this injector."""
        pass

    @abstractmethod
    def inject(self, prompt: str, constraints: Sequence[str]) -> str:
        """
        Injects security constraints or defensive instructions into the prompt.

        Args:
            prompt: Original or current prompt text.
            constraints: Sequence of security constraint strings to inject.

        Returns:
            Enhanced prompt string.
        """
        pass


__all__ = ["BaseInjector"]
