"""
Threat-Specific Policy Decision Rules.
"""

from __future__ import annotations

from typing import Sequence

from policy_engine.actions import PolicyAction
from policy_engine.config import DEFAULT_CRITICAL_THREATS
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class ThreatRule(BasePolicyRule):
    """
    Evaluates threat-specific policy overrides for critical security threats.
    """

    def __init__(self, critical_threats: Sequence[str] | None = None) -> None:
        """Initializes ThreatRule with configurable critical threats sequence."""
        if critical_threats is not None:
            self._critical_threats = set(str(t).lower().strip() for t in critical_threats)
        else:
            self._critical_threats = set(DEFAULT_CRITICAL_THREATS)

    @property
    def critical_threats(self) -> set[str]:
        """Returns configured set of critical threat names."""
        return set(self._critical_threats)

    @property
    def rule_name(self) -> str:
        return "THREAT_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        detected: set[str] = set()

        for t in context.detected_threats:
            if t:
                detected.add(str(t).lower().strip())

        if context.evidence:
            for item in context.evidence:
                ftype = getattr(item, "finding_type", None)
                if ftype:
                    detected.add(str(ftype).lower().strip())

        matched_threats = self._critical_threats.intersection(detected)
        if not matched_threats:
            for d in detected:
                if any(crit in d for crit in self._critical_threats):
                    matched_threats.add(d)

        if matched_threats:
            threat_str = ", ".join(sorted(matched_threats))
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                reason=f"Critical security threat detected [{threat_str}] overriding risk score.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "matched_threats": list(matched_threats)},
            )

        return None

