"""
Main orchestrator for the Output Guard package.

Coordinates detectors, sanitization pipeline, policy evaluation, and metadata generation.
"""

from __future__ import annotations

import logging
from typing import Sequence

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.detectors import (
    BaseOutputDetector,
    PiiDetector,
    PolicyViolationDetector,
    SecretDetector,
    SystemPromptDetector,
    ToxicDetector,
    UnsafeOutputDetector,
)
from output_guard.enums import OutputAction
from output_guard.exceptions import InvalidOutputError
from output_guard.logger import log_detection, log_final_result
from output_guard.metadata import OutputMetadataBuilder
from output_guard.models import OutputFinding, OutputSanitizationResult, SanitizationResult
from output_guard.policy import OutputPolicyEvaluator
from output_guard.sanitizer import OutputSanitizer
from output_guard.utils import measure_execution_time, truncate_output

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("output_guard.audit")


class OutputGuardEngine:
    """
    Main orchestrator engine for inspecting and guarding LLM response outputs.
    """

    def __init__(
        self,
        config: OutputGuardConfig | None = None,
        sanitizer: OutputSanitizer | None = None,
        detectors: Sequence[BaseOutputDetector] | None = None,
        policy_evaluator: OutputPolicyEvaluator | None = None,
        metadata_builder: OutputMetadataBuilder | None = None,
    ) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG
        self.sanitizer = sanitizer or OutputSanitizer(self.config)
        self.detectors = list(detectors) if detectors is not None else self._default_detectors()
        self.policy_evaluator = policy_evaluator or OutputPolicyEvaluator()
        self.metadata_builder = metadata_builder or OutputMetadataBuilder()

    def _default_detectors(self) -> list[BaseOutputDetector]:
        return [
            SecretDetector(self.config),
            SystemPromptDetector(self.config),
            PiiDetector(self.config),
            ToxicDetector(self.config),
            UnsafeOutputDetector(self.config),
            PolicyViolationDetector(self.config),
        ]

    def process(self, llm_output: str) -> OutputSanitizationResult:
        """
        Orchestrates output inspection, detection, redaction, policy evaluation, and metadata assembly.
        """
        if llm_output is None:
            if self.config.raise_on_error:
                raise InvalidOutputError("LLM output cannot be None.")
            llm_output = ""

        if not isinstance(llm_output, str):
            if self.config.raise_on_error:
                raise InvalidOutputError(f"LLM output must be a string, got {type(llm_output).__name__}.")
            llm_output = str(llm_output)

        with measure_execution_time() as elapsed:
            # 1. Truncate if exceeds maximum length
            working_output = llm_output
            if len(working_output) > self.config.max_output_length and self.config.truncate_exceeding_output:
                working_output = truncate_output(working_output, self.config.max_output_length)

            # 2. Run detectors
            detector_findings: list[OutputFinding] = []
            for detector in self.detectors:
                try:
                    findings = detector.detect(working_output)
                    for finding in findings:
                        log_detection(finding)
                        detector_findings.append(finding)
                except Exception as exc:
                    logger.error(f"Detector {detector.detector_name} failed: {exc}")
                    audit_logger.warning(
                        "[OutputGuard Audit] Detector failure: %s | Error: %s",
                        detector.detector_name,
                        exc,
                    )

            # 3. Run Sanitizer Pipeline — only if detectors found something
            if detector_findings:
                sanitization_result = self.sanitizer.sanitize(
                    working_output,
                    findings=detector_findings,
                )
            else:
                # No issues detected → pass output through without sanitization
                sanitization_result = OutputSanitizationResult(
                    original_output=working_output,
                    sanitized_output=working_output,
                    modified=False,
                    applied_sanitizers=[],
                    detected_issues=[],
                    action_taken=OutputAction.ALLOW,
                    execution_time_ms=0.0,
                    metadata={"step_results": [], "sanitizers_count": 0},
                )
            final_output = sanitization_result.sanitized_output

            # 4. Evaluate Policy Decision
            action = self.policy_evaluator.evaluate_policy(
                sanitization_results=[],
                detector_findings=detector_findings,
            )

            if sanitization_result.action_taken == OutputAction.BLOCK:
                action = OutputAction.BLOCK
            elif sanitization_result.modified and action == OutputAction.ALLOW:
                action = OutputAction.SANITIZE

            # 5. Build Metadata
            serialized_findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in detector_findings]
            meta = self.metadata_builder.build_metadata(
                original_length=len(llm_output),
                sanitized_length=len(final_output),
                execution_time_ms=elapsed(),
                step_results=sanitization_result.metadata.get("step_results", []),
                extra_metadata={
                    "detector_findings": serialized_findings,
                    "framework_version": getattr(self.config, "framework_version", "1.0.0"),
                    "module_version": getattr(self.config, "module_version", "1.0.0"),
                    "pipeline_version": getattr(self.config, "pipeline_version", "1.0.0"),
                },
            )

        return OutputSanitizationResult(
            original_output=llm_output,
            sanitized_output=final_output,
            modified=sanitization_result.modified,
            applied_sanitizers=sanitization_result.applied_sanitizers,
            detected_issues=sanitization_result.detected_issues,
            action_taken=action,
            execution_time_ms=elapsed(),
            metadata=meta,
        )
