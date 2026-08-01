"""
Purely reactive security rules for Prompt Injection and System Prompt protection.
"""

from __future__ import annotations

from typing import Any

from prompt_hardener.constraints import (
    PROMPT_INJECTION_CONSTRAINT,
    SYSTEM_PROMPT_PROTECTION,
)
from prompt_hardener.rules.base import BaseSecurityRule


class InjectionSecurityRule(BaseSecurityRule):
    """
    Applies prompt injection and system prompt protection constraints strictly
    based on RiskContext metadata and PolicyDecision action.
    Does NOT scan prompt text, use regex, or perform detection.
    """

    @property
    def rule_id(self) -> str:
        return "INJECTION_SECURITY_RULE"

    def evaluate(self, risk_context: Any, policy_decision: Any) -> list[str]:
        constraints: list[str] = []
        if risk_context is None and policy_decision is None:
            return constraints

        threats: list[str] = []
        attack_type = ""

        if risk_context is not None:
            if hasattr(risk_context, "detected_threats"):
                threats = [str(t).lower() for t in getattr(risk_context, "detected_threats", ())]
            elif isinstance(risk_context, dict):
                threats = [str(t).lower() for t in risk_context.get("detected_threats", [])]

            if hasattr(risk_context, "attack_type"):
                attack_type = str(getattr(risk_context, "attack_type", "")).lower()
            elif isinstance(risk_context, dict):
                attack_type = str(risk_context.get("attack_type", "")).lower()

        action = ""
        if hasattr(policy_decision, "action"):
            act_obj = getattr(policy_decision, "action")
            action = act_obj.value if hasattr(act_obj, "value") else str(act_obj)
        elif isinstance(policy_decision, str):
            action = policy_decision
        elif isinstance(policy_decision, dict):
            act_obj = policy_decision.get("action", "")
            action = act_obj.value if hasattr(act_obj, "value") else str(act_obj)

        action_upper = action.upper()

        injection_keywords = {
            "prompt_injection",
            "injection",
            "jailbreak",
            "prompt_extraction",
            "system_prompt_exposure",
            "role_override",
        }

        has_injection_threat = (
            any(kw in attack_type for kw in injection_keywords)
            or any(any(kw in t for kw in injection_keywords) for t in threats)
        )

        if has_injection_threat or action_upper in ("WARN", "SANITIZE"):
            constraints.append(PROMPT_INJECTION_CONSTRAINT)
            constraints.append(SYSTEM_PROMPT_PROTECTION)

        return constraints


__all__ = ["InjectionSecurityRule"]
