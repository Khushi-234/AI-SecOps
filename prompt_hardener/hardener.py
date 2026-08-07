"""
Main Orchestration Module for Prompt Hardener.
"""

from __future__ import annotations

from typing import Any, Sequence

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG
from prompt_hardener.enums import HardeningAction
from prompt_hardener.exceptions import HardeningError, InvalidPromptError
from prompt_hardener.injectors import (
    BaseInjector,
    SystemInjector,
    ConstraintInjector,
    DefenseInjector,
)
from prompt_hardener.models import HardeningResult
from prompt_hardener.rules.rule_engine import RuleEngine


class PromptHardener:
    """
    Main Prompt Hardener facade for AI-SecOps Framework v1.0.

    Responsibilities:
    
    - Receive Draft Prompt, RiskContext, and PolicyDecision.
    - Select appropriate defensive constraints via RuleEngine.
    - Inject security instructions via Injectors pipeline.
    - Strengthen the prompt to produce a Hardened Prompt payload.
    """

    def __init__(
        self,
        config: HardenerConfig | None = None,
        rule_engine: RuleEngine | None = None,
        injectors: Sequence[BaseInjector] | None = None,
    ) -> None:
        self.config = config or DEFAULT_HARDENER_CONFIG
        self.rule_engine = rule_engine or RuleEngine()

        if injectors is not None:
            self.injectors = list(injectors)
        else:
            self.injectors = [
                SystemInjector(self.config),
                ConstraintInjector(self.config),
                DefenseInjector(self.config),
            ]

    def _extract_action(self, policy_decision: Any) -> HardeningAction:
        """Helper to extract normalized HardeningAction from policy_decision."""
        if policy_decision is None:
            return HardeningAction.ALLOW

        action_val = ""
        if hasattr(policy_decision, "action"):
            act = getattr(policy_decision, "action")
            action_val = act.value if hasattr(act, "value") else str(act)
        elif isinstance(policy_decision, dict):
            act = policy_decision.get("action", "ALLOW")
            action_val = act.value if hasattr(act, "value") else str(act)
        elif isinstance(policy_decision, str):
            action_val = policy_decision
        else:
            action_val = str(policy_decision)

        try:
            return HardeningAction.from_string(action_val)
        except ValueError:
            return HardeningAction.ALLOW

    def harden(
        self,
        original_prompt: str,
        risk_context: Any = None,
        policy_decision: Any = None,
    ) -> HardeningResult:
        """
        Hardens the input prompt based strictly on Policy Engine decision and Risk Context metadata.

        Args:
            original_prompt: Raw user prompt or draft prompt string.
            risk_context: RiskContext DTO or dict from upstream Risk Engine.
            policy_decision: PolicyDecision DTO, dict, or action string from Policy Engine.

        Returns:
            HardeningResult containing original prompt, hardened prompt, action taken,
            applied injectors, added constraints, and metadata.
        """
        if original_prompt is None or not isinstance(original_prompt, str):
            raise InvalidPromptError("original_prompt must be a valid non-null string.")

        if len(original_prompt) > self.config.max_prompt_length:
            raise InvalidPromptError(
                f"Prompt length ({len(original_prompt)}) exceeds maximum limit of {self.config.max_prompt_length}."
            )

        action = self._extract_action(policy_decision)

        # 1. Action: ALLOW -> Return original prompt unchanged, forward directly to Prompt Builder
        if action == HardeningAction.ALLOW:
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_injectors=(),
                added_constraints=(),
                modified=False,
                metadata={"reason": "Action ALLOW: prompt passed unmodified."},
            )

        # 2. Action: BLOCK -> Do not modify prompt; return blocked decision immediately
        if action == HardeningAction.BLOCK:
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_injectors=(),
                added_constraints=(),
                modified=False,
                metadata={"reason": "Action BLOCK: prompt blocked without hardening.", "blocked": True},
            )

        # 3 & 4. Actions: SANITIZE and WARN
        try:
            # Step A: Evaluate Security Rules for Constraints
            constraints = self.rule_engine.evaluate_rules(
                risk_context, policy_decision
            )
            added_constraints = tuple(constraints)

            # Step B: Run Injectors Pipeline
            current_prompt = original_prompt
            applied_injectors: list[str] = []

            for injector in self.injectors:
                enhanced = injector.inject(current_prompt, added_constraints)
                if enhanced != current_prompt:
                    applied_injectors.append(injector.injector_id)
                    current_prompt = enhanced

            is_modified = (current_prompt != original_prompt)

            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=current_prompt,
                action_taken=action,
                applied_injectors=tuple(applied_injectors),
                added_constraints=added_constraints,
                modified=is_modified,
                metadata={
                    "constraints_count": len(added_constraints),
                    "injectors_count": len(applied_injectors),
                },
            )
        except Exception as exc:
            if self.config.raise_on_error:
                raise HardeningError(f"Hardening execution failed: {exc}") from exc
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_injectors=(),
                added_constraints=(),
                modified=False,
                metadata={"error": str(exc), "fallback": True},
            )


__all__ = ["PromptHardener"]
