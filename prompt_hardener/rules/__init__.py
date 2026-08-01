"""
Security Rules engine and definitions for Prompt Hardener module.
"""

from __future__ import annotations

from typing import Any, Sequence

from prompt_hardener.exceptions import RuleExecutionError
from prompt_hardener.rules.base import BaseSecurityRule
from prompt_hardener.rules.injection_rules import InjectionSecurityRule
from prompt_hardener.rules.secret_rules import SecretSecurityRule
from prompt_hardener.rules.pii_rules import PiiSecurityRule


class RuleEngine:
    """
    Evaluates configured SecurityRules against RiskContext and PolicyDecision to generate security constraints.
    """

    def __init__(self, rules: Sequence[BaseSecurityRule] | None = None) -> None:
        if rules is not None:
            self.rules = list(rules)
        else:
            self.rules = [
                InjectionSecurityRule(),
                SecretSecurityRule(),
                PiiSecurityRule(),
            ]

    def evaluate_rules(
        self, risk_context: Any, policy_decision: Any
    ) -> list[str]:
        """
        Evaluates all rules and returns deduplicated list of security constraints.

        Args:
            risk_context: RiskContext DTO or dict.
            policy_decision: PolicyDecision DTO or action string.

        Returns:
            List of distinct constraint instruction strings.
        """
        collected: list[str] = []
        seen: set[str] = set()

        for rule in self.rules:
            try:
                constraints = rule.evaluate(risk_context, policy_decision)
                for constraint in constraints:
                    if constraint and constraint not in seen:
                        seen.add(constraint)
                        collected.append(constraint)
            except Exception as exc:
                raise RuleExecutionError(
                    f"Rule '{rule.rule_id}' evaluation failed: {exc}",
                    details={"rule_id": rule.rule_id},
                ) from exc

        return collected


__all__ = [
    "BaseSecurityRule",
    "InjectionSecurityRule",
    "SecretSecurityRule",
    "PiiSecurityRule",
    "RuleEngine",
]
