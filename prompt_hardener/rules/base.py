"""
Abstract Base Class for Security Rules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseSecurityRule(ABC):
    """
    Abstract Security Rule base class.
    Security rules do NOT perform threat detection or text scanning.
    They consume only RiskContext metadata and PolicyDecision to generate security constraints.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this security rule."""
        pass

    @abstractmethod
    def evaluate(self, risk_context: Any, policy_decision: Any) -> list[str]:
        """
        Evaluates risk context metadata and returns a list of security constraint strings.

        Args:
            risk_context: RiskContext domain object or dictionary.
            policy_decision: PolicyDecision object or action string.

        Returns:
            List of canonical security constraint instruction strings from constraints.py.
        """
        pass


__all__ = ["BaseSecurityRule"]
