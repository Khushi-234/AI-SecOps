"""
Main Orchestration Module for Prompt Hardener.
"""

from __future__ import annotations

from typing import Any

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG
from prompt_hardener.enums import HardeningAction
from prompt_hardener.exceptions import HardeningError, InvalidPromptError
from prompt_hardener.models import HardeningResult
from prompt_hardener.rules import RuleEngine
from prompt_hardener.sanitizers.pipeline import SanitizerPipeline


class PromptHardener:
    """
    Main Prompt Hardener facade.
    Transforms unsafe or high-risk user prompts into safer LLM-ready prompts.

    Flow:
    User Prompt -> Input Validator -> Prompt Firewall -> Risk Engine -> Policy Engine -> Prompt Hardener -> Prompt Builder -> LLM
    """

    def __init__(
        self,
        config: HardenerConfig | None = None,
        pipeline: SanitizerPipeline | None = None,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.config = config or DEFAULT_HARDENER_CONFIG
        self.pipeline = pipeline or SanitizerPipeline(self.config)
        self.rule_engine = rule_engine or RuleEngine()

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
        Hardens the input prompt based on Policy Engine decision and Risk Context.

        Args:
            original_prompt: Raw user prompt string.
            risk_context: RiskContext DTO or dict from upstream Risk Engine.
            policy_decision: PolicyDecision DTO, dict, or action string from Policy Engine.

        Returns:
            HardeningResult containing original prompt, hardened prompt, action taken,
            applied sanitizers, added constraints, and metadata.
        """
        if original_prompt is None or not isinstance(original_prompt, str):
            raise InvalidPromptError("original_prompt must be a valid non-null string.")

        if len(original_prompt) > self.config.max_prompt_length:
            raise InvalidPromptError(
                f"Prompt length ({len(original_prompt)}) exceeds maximum limit of {self.config.max_prompt_length}."
            )

        action = self_action = self._extract_action(policy_decision)

        # 1. Action: ALLOW -> Do nothing, pass original prompt
        if action == HardeningAction.ALLOW:
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_sanitizers=(),
                added_constraints=(),
                modified=False,
                metadata={"reason": "Action ALLOW: prompt passed unmodified."},
            )

        # 2. Action: BLOCK -> Do not modify prompt; return blocked decision
        if action == HardeningAction.BLOCK:
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_sanitizers=(),
                added_constraints=(),
                modified=False,
                metadata={"reason": "Action BLOCK: prompt blocked without hardening.", "blocked": True},
            )

        # 3 & 4. Actions: SANITIZE and WARN
        try:
            # Step A: Execute Sanitization Pipeline
            sanitization_res = self.pipeline.run(original_prompt)
            sanitized_text = sanitization_res.sanitized_text
            applied_sanitizers = tuple(
                sanitization_res.metadata.get("applied_sanitizers", [])
            )

            # Step B: Evaluate Security Rules for Constraints
            constraints = self.rule_engine.evaluate_rules(
                risk_context, policy_decision
            )
            added_constraints = tuple(constraints)

            # Step C: Assemble Hardened Prompt
            hardened_text = sanitized_text
            if added_constraints:
                constraints_str = "\n".join(added_constraints)
                if hardened_text:
                    hardened_text = f"{hardened_text}\n{constraints_str}"
                else:
                    hardened_text = constraints_str

            is_modified = (hardened_text != original_prompt)

            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=hardened_text,
                action_taken=action,
                applied_sanitizers=applied_sanitizers,
                added_constraints=added_constraints,
                modified=is_modified,
                metadata={
                    "sanitization": sanitization_res.to_dict(),
                    "constraints_count": len(added_constraints),
                },
            )
        except Exception as exc:
            if self.config.raise_on_error:
                raise HardeningError(f"Hardening execution failed: {exc}") from exc
            # Fallback to returning original prompt safely if raise_on_error is False
            return HardeningResult(
                original_prompt=original_prompt,
                hardened_prompt=original_prompt,
                action_taken=action,
                applied_sanitizers=(),
                added_constraints=(),
                modified=False,
                metadata={"error": str(exc), "fallback": True},
            )


__all__ = ["PromptHardener"]
