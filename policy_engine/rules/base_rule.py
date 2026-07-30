"""
Abstract Base Interface for Policy Rules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision


class BasePolicyRule(ABC):
    """
    Abstract base class for policy rules.
    """

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Unique identifier name for this rule."""
        pass

    @abstractmethod
    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        """
        Evaluates a RiskContext payload against rule criteria.

        Args:
            context: Input RiskContext object.

        Returns:
            PolicyDecision if rule triggers, otherwise None.
        """
        pass
