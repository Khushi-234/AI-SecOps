"""
Output Guard Sanitization Pipeline.

Orchestrates sequential execution of output sanitizers in precise pipeline order:
PromptLeakSanitizer -> SecretSanitizer -> PiiSanitizer -> UnsafeOutputSanitizer -> ToxicSanitizer.
"""

from __future__ import annotations

import logging
from typing import Sequence

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.enums import OutputAction
from output_guard.exceptions import (
    InvalidOutputError,
    OutputGuardError,
    OutputGuardExecutionError,
    SanitizationError,
)
from output_guard.logger import log_pipeline, log_sanitization
from output_guard.models import OutputFinding, OutputSanitizationResult, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.sanitizers.pii_sanitizer import PiiSanitizer
from output_guard.sanitizers.prompt_leak_sanitizer import PromptLeakSanitizer
from output_guard.sanitizers.secret_sanitizer import SecretSanitizer
from output_guard.sanitizers.toxic_sanitizer import ToxicSanitizer
from output_guard.sanitizers.unsafe_output_sanitizer import UnsafeOutputSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("output_guard.audit")



class SanitizationPipeline:
    """
    Pipeline orchestrator executing sanitizers in sequence based on OutputGuardConfig.pipeline_order.
    Supports fail-secure execution and structured audit logging.
    """

    def __init__(
        self,
        config: OutputGuardConfig | None = None,
        sanitizers: Sequence[BaseSanitizer] | None = None,
    ) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG
        self.sanitizers = self._initialize_pipeline(sanitizers)

    def _initialize_pipeline(
        self, custom_sanitizers: Sequence[BaseSanitizer] | None
    ) -> list[BaseSanitizer]:
        if custom_sanitizers is not None:
            return list(custom_sanitizers)

        sanitizer_mapping: dict[str, BaseSanitizer] = {
            "prompt_leak": PromptLeakSanitizer(self.config),
            "secret": SecretSanitizer(self.config),
            "pii": PiiSanitizer(self.config),
            "unsafe": UnsafeOutputSanitizer(self.config),
            "toxic": ToxicSanitizer(self.config),
        }

        active_sanitizers: list[BaseSanitizer] = []
        order = getattr(self.config, "pipeline_order", ("prompt_leak", "secret", "pii", "unsafe", "toxic"))

        for key in order:
            norm_key = key.lower().replace("sanitizer", "").replace("_", "").replace("-", "").strip()
            for map_key, sanitizer in sanitizer_mapping.items():
                norm_map_key = map_key.lower().replace("sanitizer", "").replace("_", "").replace("-", "").strip()
                if norm_key == norm_map_key or norm_key in norm_map_key or norm_map_key in norm_key:
                    if self.config.is_sanitizer_enabled(sanitizer.sanitizer_name):
                        if sanitizer not in active_sanitizers:
                            active_sanitizers.append(sanitizer)


        return active_sanitizers


    def run(
        self,
        output: str | None,
        findings: Sequence[OutputFinding] | None = None,
    ) -> OutputSanitizationResult:
        """
        Executes the sanitization pipeline sequentially over output text.
        If findings are provided, passes them to individual sanitizers.
        """
        if output is None:
            if self.config.raise_on_error:
                raise InvalidOutputError("LLM output cannot be None.")
            output = ""

        sanitizers_to_run = self.sanitizers
        if findings is not None:
            active_finding_types = {f.finding_type for f in findings if hasattr(f, "finding_type")}
            sanitizers_to_run = [
                s for s in self.sanitizers
                if getattr(s, "sanitization_type", None) in active_finding_types
            ]

        with measure_execution_time() as elapsed:
            current_output = output
            applied_sanitizers: list[str] = []
            detected_issues: list[str] = []
            step_results: list[dict] = []
            is_modified = False

            for sanitizer in sanitizers_to_run:
                try:
                    result: SanitizationResult = sanitizer.sanitize(
                        current_output, findings=findings
                    )
                    step_results.append(result.to_dict())

                    if result.detected_issues:
                        for issue in result.detected_issues:
                            if issue not in detected_issues:
                                detected_issues.append(issue)

                    if result.is_modified:
                        is_modified = True
                        applied_sanitizers.append(sanitizer.sanitizer_name)
                        current_output = result.sanitized_output

                except Exception as exc:
                    logger.error(
                        "Sanitizer '%s' encountered error: %s",
                        sanitizer.sanitizer_name,
                        exc,
                    )
                    audit_logger.error(
                        "[OutputGuard Audit] Sanitizer Error: %s | Error: %s",
                        sanitizer.sanitizer_name,
                        exc,
                    )

                    if self.config.raise_on_error:
                        raise OutputGuardExecutionError(
                            f"Sanitizer {sanitizer.sanitizer_name} failed: {exc}",
                            details={"sanitizer_name": sanitizer.sanitizer_name},
                        ) from exc


                    if getattr(self.config, "fail_secure", True):
                        # Fail-secure fallback: block output on sanitizer failure
                        exec_time = elapsed()
                        audit_logger.warning(
                            "[OutputGuard Audit] Fail-Secure Triggered: Blocking output due to error in %s",
                            sanitizer.sanitizer_name,
                        )
                        return OutputSanitizationResult(
                            original_output=output,
                            sanitized_output="[RESPONSE_BLOCKED_DUE_TO_SANITY_CHECK_FAILURE]",
                            modified=True,
                            applied_sanitizers=applied_sanitizers + [sanitizer.sanitizer_name],
                            detected_issues=detected_issues + [f"Sanitizer failure: {sanitizer.sanitizer_name}"],
                            action_taken=OutputAction.BLOCK,
                            execution_time_ms=exec_time,
                            metadata={"fail_secure": True, "failed_sanitizer": sanitizer.sanitizer_name},
                        )

            action = OutputAction.SANITIZE if is_modified else OutputAction.ALLOW
            exec_time = elapsed()

            audit_logger.info(
                "[OutputGuard Audit] Pipeline Completed | Action: %s | Modified: %s | Applied: %d | Time: %.2fms",
                action,
                is_modified,
                len(applied_sanitizers),
                exec_time,
            )

        return OutputSanitizationResult(
            original_output=output,
            sanitized_output=current_output,
            modified=is_modified,
            applied_sanitizers=applied_sanitizers,
            detected_issues=detected_issues,
            action_taken=action,
            execution_time_ms=exec_time,
            metadata={
                "sanitizers_count": len(self.sanitizers),
                "step_results": step_results,
            },
        )


__all__ = ["SanitizationPipeline"]
