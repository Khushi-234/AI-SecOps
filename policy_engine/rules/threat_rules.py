"""
Threat-Specific Policy Decision Rules.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class ThreatRule(BasePolicyRule):
    """
    Evaluates threat-specific policy overrides for critical security threats.
    """

    CRITICAL_THREATS = {
        "credential_leak",
        "secret_exposure",
        "system_prompt_extraction",
        "severe_jailbreak",
        "prompt_injection",
        "jailbreak",
        "secret_leak",
        "pii_leak",
    }

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

        matched_threats = self.CRITICAL_THREATS.intersection(detected)
        if not matched_threats:
            for d in detected:
                if any(crit in d for crit in self.CRITICAL_THREATS):
                    matched_threats.add(d)

        if matched_threats:
            threat_str = ", ".join(sorted(matched_threats))
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                final_prompt=None,
                reason=f"Critical security threat detected [{threat_str}] overriding risk score.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "matched_threats": list(matched_threats)},
            )

        return None
