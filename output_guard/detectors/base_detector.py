"""
Abstract base class for Output Guard detectors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.models import OutputFinding


class BaseOutputDetector(ABC):
    """
    Abstract Base Class for all Output Guard detectors.
    """

    def __init__(self, config: OutputGuardConfig | None = None) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Unique identifier of the detector."""
        pass

    @abstractmethod
    def detect(self, output_text: str) -> list[OutputFinding]:
        """
        Scans output text and returns a list of detected OutputFinding DTOs.
        """
        pass

