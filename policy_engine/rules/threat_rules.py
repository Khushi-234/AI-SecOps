"""
Threat-Specific Policy Decision Rules.

Evaluates specific detected security threat types (e.g., credential_leak, secret_exposure,
system_prompt_extraction, severe_jailbreak) which override general risk scores and enforce BLOCK.
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
        return "CRITICAL_THREAT_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        detected: set[str] = set()

        # Check detected_threats list
        for t in context.detected_threats:
            detected.add(str(t).lower().strip())

        # Check evidence findings for threat types
        if context.evidence:
            for item in context.evidence:
                ftype = getattr(item, "finding_type", None)
                if ftype:
                    detected.add(str(ftype).lower().strip())

        # Match against critical threat catalog
        matched_threats = self.CRITICAL_THREATS.intersection(detected)

        # Also check substring matches for custom threat identifiers
        if not matched_threats:
            for d in detected:
                if any(crit in d for crit in self.CRITICAL_THREATS):
                    matched_threats.add(d)

        if matched_threats:
            threat_str = ", ".join(sorted(matched_threats))
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                reason=f"Critical security threat detected [{threat_str}] overriding risk score ({context.risk_score}).",
                risk_score=context.risk_score,
                rule_triggered=f"THREAT_RULE_{threat_str.upper()}",
            )

        return None
