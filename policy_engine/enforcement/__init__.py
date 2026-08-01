"""
Enforcement Layer Orchestrator.

Dispatches decided PolicyActions (ALLOW, WARN, SANITIZE, BLOCK) to dedicated action enforcers.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.enforcement.allow import AllowEnforcer
from policy_engine.enforcement.block import BlockEnforcer
from policy_engine.enforcement.sanitize import SanitizeEnforcer
from policy_engine.enforcement.warn import WarnEnforcer
from policy_engine.models import PolicyDecision



class EnforcementLayer:
    """
    Enforcement Layer dispatcher delegating decided PolicyDecision execution.
    """

    def __init__(self) -> None:
        self._allow_enforcer = AllowEnforcer()
        self._warn_enforcer = WarnEnforcer()
        self._sanitize_enforcer = SanitizeEnforcer()
        self._block_enforcer = BlockEnforcer()

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        """
        Executes enforcement action based on PolicyDecision.

        Args:
            decision: Evaluated PolicyDecision.
            context: Input RiskContext object.

        Returns:
            Enforced PolicyDecision containing final output fields.
        """
        action = (
            decision.action
            if isinstance(decision.action, PolicyAction)
            else PolicyAction.from_string(str(decision.action))
        )

        if action == PolicyAction.BLOCK:
            return self._block_enforcer.enforce(decision, context)
        elif action == PolicyAction.SANITIZE:
            return self._sanitize_enforcer.enforce(decision, context)
        elif action == PolicyAction.WARN:
            return self._warn_enforcer.enforce(decision, context)
        else:
            return self._allow_enforcer.enforce(decision, context)


__all__ = [
    "EnforcementLayer",
    "AllowEnforcer",
    "WarnEnforcer",
    "SanitizeEnforcer",
    "BlockEnforcer",
]

