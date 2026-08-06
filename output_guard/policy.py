"""
Output Guard Policy Decision Logic.

Evaluates detector findings and sanitization results to determine final OutputAction.
"""

from __future__ import annotations

from typing import Sequence

from output_guard.enums import FindingType, OutputAction, OutputSeverity
from output_guard.models import OutputFinding, SanitizationResult


class OutputPolicyEvaluator:
    """
    Evaluates safety findings and determines policy actions for LLM outputs.
    Action Priority Enforcement: BLOCK > SANITIZE > WARN > ALLOW.
    """

    def evaluate_policy(
        self,
        sanitization_results: Sequence[SanitizationResult],
        detector_findings: Sequence[OutputFinding] | None = None,
    ) -> OutputAction:
        """
        Determines final OutputAction (BLOCK > SANITIZE > WARN > ALLOW).
        """
        findings = [f for f in (detector_findings or []) if isinstance(f, OutputFinding)]
        results = list(sanitization_results)

        # 1. Highest Priority: BLOCK
        for finding in findings:
            ftype = str(finding.finding_type).upper()
            sev = str(finding.severity).upper()
            if ftype in (FindingType.UNSAFE_CODE.value, "UNSAFE_CODE") or sev in (OutputSeverity.CRITICAL.value, "CRITICAL"):
                return OutputAction.BLOCK

        # 2. Second Priority: SANITIZE
        if any(res.is_modified for res in results):
            return OutputAction.SANITIZE

        # 3. Third Priority: WARN
        for finding in findings:
            ftype = str(finding.finding_type).upper()
            if ftype in (FindingType.TOXIC_CONTENT.value, FindingType.PROMPT_LEAK.value, "TOXIC_CONTENT", "PROMPT_LEAK"):
                return OutputAction.WARN

        # 4. Lowest Priority: ALLOW
        return OutputAction.ALLOW