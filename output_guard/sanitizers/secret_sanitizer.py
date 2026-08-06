"""
Sanitizer for redacting sensitive credentials and secrets from LLM output.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from output_guard.constants import SANITIZER_SECRET_NAME
from output_guard.enums import FindingType, SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import OutputFinding, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class SecretSanitizer(BaseSanitizer):
    """
    Sanitizes sensitive secrets (API keys, tokens, passwords, credentials, private keys)
    from LLM generated responses by consuming OutputFinding objects from SecretDetector.
    Does not run independent regex pattern detection.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_SECRET_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.SECRET

    def _get_replacement_for_finding(self, finding: OutputFinding) -> str:
        """Helper to get replacement token for secret findings."""
        return self.config.secret_replacement

    def sanitize(
        self,
        output: str,
        findings: Sequence[OutputFinding] | None = None,
    ) -> SanitizationResult:
        """
        Redacts detected secret values from output text using provided findings.
        """
        if not output:
            return SanitizationResult(
                sanitizer_name=self.sanitizer_name,
                sanitization_type=self.sanitization_type,
                is_modified=False,
                original_output=output or "",
                sanitized_output=output or "",
                changes=[],
                detected_issues=[],
                execution_time_ms=0.0,
            )

        with measure_execution_time() as elapsed:
            current_text = output
            changes: list[dict[str, Any]] = []
            detected_issues: list[str] = []
            total_replacements = 0

            if findings:
                try:
                    for finding in findings:
                        if getattr(finding, "finding_type", None) != FindingType.SECRET:
                            continue

                        secret_type = (
                            finding.metadata.get("secret_category")
                            or finding.metadata.get("secret_type")
                            or "secret"
                        ) if finding.metadata else "secret"
                        replacement_token = self._get_replacement_for_finding(finding)
                        matches = getattr(finding, "matches", ()) or ()
                        finding_count = 0

                        for match in matches:
                            if match and match in current_text:
                                match_occurrences = current_text.count(match)
                                if match_occurrences > 0:
                                    current_text = current_text.replace(match, replacement_token)
                                    finding_count += match_occurrences

                        if finding_count > 0:
                            total_replacements += finding_count
                            issue_msg = f"Detected secret ({secret_type})"
                            if issue_msg not in detected_issues:
                                detected_issues.append(issue_msg)
                            changes.append(
                                {
                                    "secret_type": secret_type,
                                    "count": finding_count,
                                    "replacement": replacement_token,
                                }
                            )

                except Exception as e:
                    logger.error(f"Error in SecretSanitizer execution: {e}")
                    if self.config.raise_on_error:
                        raise SanitizationError(
                            f"SecretSanitizer failed: {str(e)}",
                            sanitizer_name=self.sanitizer_name,
                        ) from e

            is_modified = total_replacements > 0

        return SanitizationResult(
            sanitizer_name=self.sanitizer_name,
            sanitization_type=self.sanitization_type,
            is_modified=is_modified,
            original_output=output,
            sanitized_output=current_text,
            changes=changes,
            detected_issues=detected_issues,
            execution_time_ms=elapsed(),
            metadata={"replacements_count": total_replacements},
        )


__all__ = ["SecretSanitizer"]
