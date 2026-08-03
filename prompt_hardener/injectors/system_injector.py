"""
System Injector for strengthening system instructions and prompt integrity.
"""

from __future__ import annotations

from typing import Sequence

from prompt_hardener.constraints import SYSTEM_PROMPT_PROTECTION
from prompt_hardener.injectors.base_injector import BaseInjector


class SystemInjector(BaseInjector):
    """
    Injects system-level defensive instructions to reinforce prompt integrity,
    prevent role overrides, and preserve system boundaries.
    Does NOT perform attack detection.
    """

    @property
    def injector_id(self) -> str:
        return "SYSTEM_INJECTOR"

    def inject(self, prompt: str, constraints: Sequence[str]) -> str:
        """
        Strengthens prompt with immutable system protection rules.
        """
        if not prompt:
            return f"[SYSTEM DEFENSE]: {SYSTEM_PROMPT_PROTECTION}"
            
        if SYSTEM_PROMPT_PROTECTION in constraints:
            return f"{prompt}\n[SYSTEM DEFENSE]: {SYSTEM_PROMPT_PROTECTION}"

        return prompt


__all__ = ["SystemInjector"]
