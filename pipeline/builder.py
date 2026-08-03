"""
AISecOpsPipelineBuilder for fluent dependency injection and custom pipeline assembly.
"""

from __future__ import annotations

from typing import Optional

from input_validator.input_validator import InputValidator
from llm.base_provider import BaseLLMProvider
from llm.prompt_builder import PromptBuilder
from output_guard.facade import OutputGuardFacade
from pipeline.config import PipelineConfig
from pipeline.logger import PipelineLogger
from pipeline.pipeline import AISecOpsPipeline
from policy_engine.engine import PolicyEngine
from prompt_hardener.hardener import PromptHardener
from risk_engine.engine import RiskEngine
from security.prompt_firewall import PromptFirewall


class AISecOpsPipelineBuilder:
    """
    Fluent builder class for instantiating AISecOpsPipeline instances.
    """

    def __init__(self) -> None:
        self._config: Optional[PipelineConfig] = None
        self._input_validator: Optional[InputValidator] = None
        self._prompt_builder: Optional[PromptBuilder] = None
        self._prompt_firewall: Optional[PromptFirewall] = None
        self._risk_engine: Optional[RiskEngine] = None
        self._policy_engine: Optional[PolicyEngine] = None
        self._prompt_hardener: Optional[PromptHardener] = None
        self._llm_provider: Optional[BaseLLMProvider] = None
        self._output_guard: Optional[OutputGuardFacade] = None
        self._logger: Optional[PipelineLogger] = None

    def with_config(self, config: PipelineConfig) -> AISecOpsPipelineBuilder:
        """Sets custom PipelineConfig."""
        self._config = config
        return self

    def with_input_validator(
        self, input_validator: InputValidator
    ) -> AISecOpsPipelineBuilder:
        """Injects custom InputValidator instance."""
        self._input_validator = input_validator
        return self

    def with_prompt_builder(
        self, prompt_builder: PromptBuilder
    ) -> AISecOpsPipelineBuilder:
        """Injects custom PromptBuilder instance."""
        self._prompt_builder = prompt_builder
        return self

    def with_prompt_firewall(
        self, prompt_firewall: PromptFirewall
    ) -> AISecOpsPipelineBuilder:
        """Injects custom PromptFirewall instance."""
        self._prompt_firewall = prompt_firewall
        return self

    def with_risk_engine(self, risk_engine: RiskEngine) -> AISecOpsPipelineBuilder:
        """Injects custom RiskEngine instance."""
        self._risk_engine = risk_engine
        return self

    def with_policy_engine(self, policy_engine: PolicyEngine) -> AISecOpsPipelineBuilder:
        """Injects custom PolicyEngine instance."""
        self._policy_engine = policy_engine
        return self

    def with_prompt_hardener(
        self, prompt_hardener: PromptHardener
    ) -> AISecOpsPipelineBuilder:
        """Injects custom PromptHardener instance."""
        self._prompt_hardener = prompt_hardener
        return self

    def with_llm_provider(
        self, llm_provider: BaseLLMProvider
    ) -> AISecOpsPipelineBuilder:
        """Injects custom BaseLLMProvider instance."""
        self._llm_provider = llm_provider
        return self

    def with_output_guard(
        self, output_guard: OutputGuardFacade
    ) -> AISecOpsPipelineBuilder:
        """Injects custom OutputGuardFacade instance."""
        self._output_guard = output_guard
        return self

    def with_logger(self, logger: PipelineLogger) -> AISecOpsPipelineBuilder:
        """Injects custom PipelineLogger instance."""
        self._logger = logger
        return self

    def build(self) -> AISecOpsPipeline:
        """Constructs and returns configured AISecOpsPipeline instance."""
        return AISecOpsPipeline(
            config=self._config,
            input_validator=self._input_validator,
            prompt_builder=self._prompt_builder,
            prompt_firewall=self._prompt_firewall,
            risk_engine=self._risk_engine,
            policy_engine=self._policy_engine,
            prompt_hardener=self._prompt_hardener,
            llm_provider=self._llm_provider,
            output_guard=self._output_guard,
            logger=self._logger,
        )
