"""
Constraint Injector for injecting security constraints into prompt payloads.
"""

from __future__ import annotations

from typing import Sequence

from prompt_hardener.injectors.base_injector import BaseInjector


class ConstraintInjector(BaseInjector):
    """
    Injects selected security constraints into the prompt payload.
    """

    @property
    def injector_id(self) -> str:
        return "CONSTRAINT_INJECTOR"

    def inject(self, prompt: str, constraints: Sequence[str]) -> str:
        """
        Appends security constraints to the prompt string.
        """
        if not constraints:
            return prompt

        formatted_constraints = "\n".join(constraints)
        if not prompt:
            return formatted_constraints

        return f"{prompt}\n{formatted_constraints}"


__all__ = ["ConstraintInjector"]
