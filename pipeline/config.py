"""
PipelineConfig container aggregating global pipeline settings and module-specific configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from input_validator.config import InputValidatorConfig
from output_guard.config import OutputGuardConfig
from policy_engine.config import PolicyEngineConfig
from prompt_hardener.config import HardenerConfig
from risk_engine.config import RiskEngineConfig


@dataclass(slots=True)
class PipelineConfig:
    """
    Central configuration container for AISecOpsPipeline.

    Attributes:
        fail_secure_default: Default fail-secure strategy if unhandled error occurs.
        strict_policy_enforcement: If True, DENY policies abort downstream execution.
        default_provider_name: Default LLM provider string identifier.
        input_validator_config: Configuration for InputValidator module.
        risk_engine_config: Configuration for RiskEngine module.
        policy_engine_config: Configuration for PolicyEngine module.
        prompt_hardener_config: Configuration for PromptHardener module.
        output_guard_config: Configuration for OutputGuardFacade module.
        custom_settings: Dictionary for auxiliary pipeline settings.
    """

    fail_secure_default: bool = True
    strict_policy_enforcement: bool = True
    default_provider_name: str = "groq"

    input_validator_config: InputValidatorConfig = field(
        default_factory=InputValidatorConfig
    )
    risk_engine_config: RiskEngineConfig = field(default_factory=RiskEngineConfig)
    policy_engine_config: PolicyEngineConfig = field(
        default_factory=PolicyEngineConfig
    )
    prompt_hardener_config: HardenerConfig = field(default_factory=HardenerConfig)
    output_guard_config: OutputGuardConfig = field(default_factory=OutputGuardConfig)

    custom_settings: Dict[str, Any] = field(default_factory=dict)
