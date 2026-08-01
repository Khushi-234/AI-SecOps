"""
Output Guard Module for AI-SecOps Framework.

Responsible for checking and sanitizing LLM-generated outputs before returning them to users.
"""

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.enums import OutputAction, SanitizationType
from output_guard.exceptions import (
    ConfigurationError,
    InvalidOutputError,
    OutputGuardError,
    SanitizationError,
)
from output_guard.models import OutputSanitizationResult, SanitizationResult
from output_guard.sanitizer import OutputGuard, OutputSanitizer

__all__ = [
    "OutputGuard",
    "OutputSanitizer",
    "OutputSanitizationResult",
    "SanitizationResult",
    "OutputAction",
    "SanitizationType",
    "OutputGuardConfig",
    "DEFAULT_OUTPUT_GUARD_CONFIG",
    "OutputGuardError",
    "SanitizationError",
    "InvalidOutputError",
    "ConfigurationError",
]
