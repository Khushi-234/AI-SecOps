"""
Purely reactive security rules for Personally Identifiable Information (PII) protection.
"""

from __future__ import annotations

from typing import Any

from prompt_hardener.constraints import PII_PROTECTION_CONSTRAINT
from prompt_hardener.rules.base import BaseSecurityRule


class PiiSecurityRule(BaseSecurityRule):
    """
    Applies PII protection constraint strictly based on RiskContext metadata.
    Does NOT scan prompt text or perform detection.
    """

    @property
    def rule_id(self) -> str:
        return "PII_SECURITY_RULE"

    def evaluate(self, risk_context: Any, policy_decision: Any) -> list[str]:
        constraints: list[str] = []
        if risk_context is None:
            return constraints

        threats: list[str] = []
        attack_type = ""

        if hasattr(risk_context, "detected_threats"):
            threats = [str(t).lower() for t in getattr(risk_context, "detected_threats", ())]
        elif isinstance(risk_context, dict):
            threats = [str(t).lower() for t in risk_context.get("detected_threats", [])]

        if hasattr(risk_context, "attack_type"):
            attack_type = str(getattr(risk_context, "attack_type", "")).lower()
        elif isinstance(risk_context, dict):
            attack_type = str(risk_context.get("attack_type", "")).lower()

        pii_keywords = {
            "pii",
            "pii_leak",
            "personal_data",
            "privacy",
            "email",
            "phone",
            "ssn",
        }

        has_pii_threat = (
            any(kw in attack_type for kw in pii_keywords)
            or any(any(kw in t for kw in pii_keywords) for t in threats)
        )

        if has_pii_threat:
            constraints.append(PII_PROTECTION_CONSTRAINT)

        return constraints


__all__ = ["PiiSecurityRule"]
