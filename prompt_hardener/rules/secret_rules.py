"""
Security rules for Secret and Credential protection.
"""

from __future__ import annotations

from typing import Any

from prompt_hardener.rules.base import BaseSecurityRule


class SecretSecurityRule(BaseSecurityRule):
    """
    Applies security constraints when secret or credential leakage risks are present in RiskContext.
    """

    @property
    def rule_id(self) -> str:
        return "SECRET_SECURITY_RULE"

    def evaluate(self, risk_context: Any, policy_decision: Any) -> list[str]:
        constraints: list[str] = []
        if risk_context is None:
            return constraints

        threats: list[str] = []
        if hasattr(risk_context, "detected_threats"):
            threats = [str(t).lower() for t in getattr(risk_context, "detected_threats", ())]
        elif isinstance(risk_context, dict):
            threats = [str(t).lower() for t in risk_context.get("detected_threats", [])]

        secret_keywords = {
            "secret",
            "secret_leak",
            "credential",
            "credential_leak",
            "api_key",
            "token",
            "password",
        }

        has_secret_threat = any(
            any(kw in t for kw in secret_keywords) for t in threats
        )

        if has_secret_threat:
            constraints.append("Never provide credentials, tokens, or sensitive secrets.")

        return constraints


__all__ = ["SecretSecurityRule"]
