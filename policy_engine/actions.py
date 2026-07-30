"""
Policy Action Enumeration and Priority Constants.

Defines canonical PolicyAction enum and action priority levels for the Policy Engine.
"""

from __future__ import annotations
from policy_engine.enums import BaseStringEnum

class PolicyAction(BaseStringEnum):
    """
    Core security decision actions emitted by the Policy Engine.
    """

    ALLOW = "ALLOW"
    WARN = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"

# Priority Hierarchy (Higher integer = Higher enforcement priority)
ACTION_PRIORITY: dict[PolicyAction, int] = {
    PolicyAction.BLOCK: 4,     # Highest priority
    PolicyAction.SANITIZE: 3,
    PolicyAction.WARN: 2,
    PolicyAction.ALLOW: 1,     # Lowest priority
}
