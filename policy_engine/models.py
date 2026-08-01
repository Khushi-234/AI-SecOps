"""
Immutable Domain Data Models for the Policy Engine.

Defines canonical Data Transfer Objects (DTOs) for Policy Engine decision contexts
and policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext


@dataclass(slots=True, frozen=True)
class PolicyDecision:
    """
    Canonical decision payload produced by the Policy Engine.

    Required Fields:
        action: PolicyAction enum ('ALLOW', 'WARN', 'SANITIZE', 'BLOCK').
        reason: Rationale justifying the decision.
        risk_score: Risk score evaluated [0-100 or 0.0-1.0].
        rule_triggered: Name of the primary rule triggering this decision.
        timestamp: Timezone-aware UTC timestamp.
        metadata: Diagnostic and execution metadata.

    Enforcement Output Fields:
        is_approved: True for ALLOW, WARN, SANITIZE; False for BLOCK.
        request_id: Optional request identifier for correlation.
        matched_rules: Tuple of rule identifiers that evaluated on this request.
    """

    action: PolicyAction | str
    reason: str
    risk_score: float = 0.0
    rule_triggered: str = "DEFAULT_RULE"
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # Enforcement details
    is_approved: bool = True
    request_id: str = ""
    matched_rules: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validates decision consistency and field types."""
        action_obj = (
            PolicyAction.from_string(self.action)
            if isinstance(self.action, str) and PolicyAction.has_value(self.action)
            else self.action
        )
        object.__setattr__(self, "action", action_obj)

        if not isinstance(self.matched_rules, tuple):
            object.__setattr__(self, "matched_rules", tuple(self.matched_rules))

        # Enforce is_approved consistency based on action
        action_val = self.action.value if isinstance(self.action, Enum) else str(self.action)
        if action_val == PolicyAction.BLOCK.value:
            object.__setattr__(self, "is_approved", False)

    def to_dict(self) -> dict[str, Any]:
        """Serializes PolicyDecision to standard dictionary payload."""
        return {
            "request_id": self.request_id,
            "action": (
                self.action.value if isinstance(self.action, Enum) else str(self.action)
            ),
            "reason": self.reason,
            "risk_score": self.risk_score,
            "rule_triggered": self.rule_triggered,
            "is_approved": self.is_approved,
            "matched_rules": list(self.matched_rules),
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }

