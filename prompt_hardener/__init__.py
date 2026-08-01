"""
Prompt Hardener Module for AI-SecOps Framework.

Transforms unsafe or high-risk prompts into safer LLM-ready prompts.
"""

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG
from prompt_hardener.enums import HardeningAction, SanitizationType
from prompt_hardener.exceptions import (
    HardeningError,
    SanitizationError,
    RuleExecutionError,
    InvalidPromptError,
    ConfigurationError,
)
from prompt_hardener.hardener import PromptHardener
from prompt_hardener.models import HardeningResult, SanitizationResult

__all__ = [
    "PromptHardener",
    "HardenerConfig",
    "DEFAULT_HARDENER_CONFIG",
    "HardeningAction",
    "SanitizationType",
    "HardeningResult",
    "SanitizationResult",
    "HardeningError",
    "SanitizationError",
    "RuleExecutionError",
    "InvalidPromptError",
    "ConfigurationError",
]
