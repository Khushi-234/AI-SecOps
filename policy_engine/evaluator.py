"""
Policy Rule Evaluator and Priority Resolver Engine.

Loads policy rules, executes evaluation against RiskContext, collects rule decisions,
and resolves the final decision based on strict priority (BLOCK > SANITIZE > WARN > ALLOW).
"""

from __future__ import annotations

from typing import Sequence

from policy_engine.actions import ACTION_PRIORITY, PolicyAction
from policy_engine.context import RiskContext
from policy_engine.logger import log_policy_decision
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule
from policy_engine.rules.risk_rules import RiskScoreRule
from policy_engine.rules.severity_rules import SeverityRule
from policy_engine.rules.threat_rules import ThreatRule


class PolicyEvaluator:
    """
    Evaluates RiskContext against registered policy rules and resolves action priorities.
    """

    def __init__(self, rules: Sequence[BasePolicyRule] | None = None) -> None:
        """Initializes evaluator with given rules or default rule catalog."""
        if rules is not None:
            self._rules: list[BasePolicyRule] = list(rules)
        else:
            # Default Rule Order: ThreatRule -> RiskScoreRule -> SeverityRule
            self._rules = [
                ThreatRule(),
                RiskScoreRule(),
                SeverityRule(),
            ]

    @property
    def rules(self) -> list[BasePolicyRule]:
        """Returns registered rules."""
        return list(self._rules)

    def evaluate(self, context: RiskContext) -> PolicyDecision:
        """
        Evaluates RiskContext against all registered rules and returns the priority-resolved PolicyDecision.

        Args:
            context: Input RiskContext object.

        Returns:
            Resolved PolicyDecision payload.
        """
        decisions: list[PolicyDecision] = []

        for rule in self._rules:
            decision = rule.evaluate(context)
            if decision is not None:
                decisions.append(decision)

        if not decisions:
            # Default fallback if no rule triggered
            resolved = PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.ALLOW,
                reason=f"Default ALLOW decision for request {context.request_id}.",
                risk_score=context.risk_score,
                rule_triggered="DEFAULT_ALLOW",
            )
        else:
            # Resolve priority: Highest action priority (BLOCK > SANITIZE > WARN > ALLOW)
            resolved = self._resolve_priority(decisions)

        # Log structured audit telemetry
        action_str = (
            resolved.action.value
            if isinstance(resolved.action, PolicyAction)
            else str(resolved.action)
        )
        log_policy_decision(
            request_id=resolved.request_id or context.request_id,
            action=action_str,
            reason=resolved.reason,
            risk_score=resolved.risk_score,
            rule_triggered=resolved.rule_triggered,
            metadata=dict(resolved.metadata),
        )

        return resolved

    def _resolve_priority(
        self, decisions: Sequence[PolicyDecision]
    ) -> PolicyDecision:
        """
        Resolves multiple rule decisions using the Policy Priority System:
        BLOCK (4) > SANITIZE (3) > WARN (2) > ALLOW (1).
        """
        best_decision: PolicyDecision = decisions[0]
        best_priority = self._get_action_priority(best_decision.action)

        for dec in decisions[1:]:
            prio = self._get_action_priority(dec.action)
            if prio > best_priority:
                best_decision = dec
                best_priority = prio

        return best_decision

    @staticmethod
    def _get_action_priority(action: PolicyAction | str) -> int:
        """Returns integer priority rating for an action (higher = higher priority)."""
        if isinstance(action, str):
            try:
                action_enum = PolicyAction.from_string(action)
                return ACTION_PRIORITY.get(action_enum, 1)
            except ValueError:
                return 1
        return ACTION_PRIORITY.get(action, 1)
