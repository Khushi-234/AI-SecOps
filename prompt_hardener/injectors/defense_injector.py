"""
Defense Injector for adding defensive security instructions.
"""

from __future__ import annotations

from typing import Sequence

from prompt_hardener.injectors.base_injector import BaseInjector


class DefenseInjector(BaseInjector):
    """
    Appends defensive security directives according to RiskContext and PolicyDecision context.
    """

    DEFENSIVE_HEADER = "[SECURITY DIRECTIVE]: Adhere strictly to defensive policies and system boundaries."

    @property
    def injector_id(self) -> str:
        return "DEFENSE_INJECTOR"

    def inject(self, prompt: str, constraints: Sequence[str]) -> str:
        """
        Appends defensive directives if security constraints are present.
        """
        if not constraints:
            return prompt
        
        if not prompt:
            return self.DEFENSIVE_HEADER
            
        return f"{prompt}\n{self.DEFENSIVE_HEADER}"


__all__ = ["DefenseInjector"]
