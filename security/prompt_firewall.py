from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from security.audit_logger import AuditLogger
from security.base_detector import BaseDetector
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.exceptions import DetectorExecutionError, FirewallError, NormalizationError, ValidationError
from security.models import DetectionResult, FirewallResponse
from security.normalizer import TextNormalizer

class PromptFirewall:
    """
    Main gateway security orchestrator that coordinates the prompt validation pipeline.

    Purpose:
    --------
    Acts as the entry point for prompt validation. It normalizes inputs, executes 
    a suite of registered security detectors, aggregates findings, and logs 
    telemetry without executing threat evaluation or request blocking themselves.

    Pipeline Steps:
    ---------------
    1. Input Validation: Verifies that the prompt is a non-null string instance.
    2. Timing: Starts a high-resolution timer.
    3. Normalization: Invokes TextNormalizer.normalize_text() to strip evasions.
    4. Execution: Runs all configured detectors sequentially (fail_fast is inactiv/.;e).
    5. Isolation: Intercepts detector execution exceptions under fail_secure conditions.
    6. Logging: Invokes AuditLogger.log_event() exactly once.
    7. Response: Packages results into a FirewallResponse DTO.

    Responsibilities:
    -----------------
    - Client prompt reception and validation.
    - Delegation of string cleaning to TextNormalizer.
    - Dynamic dispatch of inspection checks to BaseDetector subclasses.
    - Integration-level error mapping and timing calculations.
    - Routing audit events exactly once to AuditLogger.

    Responsibilities NOT Included:
    ------------------------------
    - Does NOT contain regex matching logic or rule databases.
    - Does NOT calculate composite/overall risk scores (delegated to Risk Engine).
    - Does NOT enforce compliance routing or block requests (delegated to Policy Engine).
    - Does NOT communicate directly with databases or invoke external LLMs.

    Dependency Inversion Principle (SOLID):
    ---------------------------------------
    PromptFirewall depends entirely on abstract base classes (BaseDetector, AuditLogger) 
    rather than concrete implementations. This decouples orchestration from specific 
    scanning rules or storage drivers, allowing other teams to register new detectors 
    or loggers dynamically.

    OWASP Alignment:
    ----------------
    Serves as the framework's primary gateway defense layer, ensuring that incoming prompts 
    are preprocessed and validated against OWASP LLM01 (Prompt Injection) threat patterns 
    prior to model execution.

    Time Complexity:
    ----------------
    O(M * N) linear time, where M is the number of active pipeline detectors and N is 
    the character size of the prompt.

    Space Complexity:
    -----------------
    O(N) memory to hold intermediate text copies and aggregated DetectionResult objects.

    Future Integrations:
    --------------------
    - Risk Engine (Sprint 7): Consumes the flat list of DetectionResult objects inside 
      FirewallResponse to compute a unified framework risk index.
      (e.g., RiskEngine.evaluate_risk(firewall_response.results)).
    - Policy Engine (Sprint 8): Evaluates the compiled scan metrics against compliance 
      policies to make final routing, filtering, or request-blocking decisions.
      (e.g., PolicyEngine.enforce_policy(firewall_response)).
    - Output Guard (Sprint 9): Executes post-generation guardrails on LLM completions.
    """

    def __init__(
        self,
        detectors: list[BaseDetector],
        audit_logger: AuditLogger,
        normalizer: TextNormalizer,
        fail_secure: bool = True
    ) -> None:
        """
        Initializes the PromptFirewall.

        Args:
            detectors: Sequential pipeline of detectors implementing BaseDetector.
            audit_logger: A logging interface implementing AuditLogger.
            normalizer: A text normalizer class instance.
            fail_secure: If True, detector runtime errors default to security violations.
        """
        self._detectors = detectors
        self._audit_logger = audit_logger
        self._normalizer = normalizer
        self._fail_secure = fail_secure

    def inspect_prompt(self, prompt: str, context: dict[str, Any] | None = None) -> FirewallResponse:
        """
        Inspects a prompt string by executing the full validation pipeline.

        Args:
            prompt: The raw user prompt.
            context: Correlation and session metadata.

        Returns:
            FirewallResponse: Compiled results and timing statistics.

        Raises:
            ValidationError: If input validation constraints are violated.
            NormalizationError: If validation constraints inside normalizer are violated.
            FirewallError: If core pipeline or normalizer components fail.
        """
        if prompt is None:
            raise ValidationError("Prompt cannot be None")
        if not isinstance(prompt, str):
            raise ValidationError("Prompt must be a string instance")

        start_time = time.perf_counter()

        # Normalize prompt (allowing ValidationError and NormalizationError to propagate naturally)
        try:
            norm_result = self._normalizer.normalize_text(prompt)
            normalized_prompt = norm_result.normalized_text
            norm_metadata = norm_result.metadata
        except (ValidationError, NormalizationError):
            raise
        except Exception as e:
            raise FirewallError(f"Normalizer failed unexpectedly: {e}") from e

        request_id = context.get("request_id", "unknown") if context else "unknown"
        results: list[DetectionResult] = []

        # Execute every detector sequentially
        for detector in self._detectors:
            detector_start = time.perf_counter()
            try:
                result = detector.detect(normalized_prompt, context)
                results.append(result)
            except DetectorExecutionError as dee:
                if self._fail_secure:
                    detector_elapsed = (time.perf_counter() - detector_start) * 1000.0
                    error_result = self._build_error_result(detector, request_id, detector_elapsed, dee)
                    results.append(error_result)
                else:
                    raise
            except Exception as e:
                wrapped_error = DetectorExecutionError(f"Unexpected detector execution crash: {e}")
                if self._fail_secure:
                    detector_elapsed = (time.perf_counter() - detector_start) * 1000.0
                    error_result = self._build_error_result(detector, request_id, detector_elapsed, e)
                    results.append(error_result)
                else:
                    raise wrapped_error from e

        # Calculate total latency
        total_time_ms = (time.perf_counter() - start_time) * 1000.0

        # Create response DTO
        response = FirewallResponse(
            request_id=request_id,
            normalized_prompt=normalized_prompt,
            results=results,
            execution_time_ms=total_time_ms
        )

        # Call log_event exactly once (safeguarded to prevent logging failures from blocking responses)
        details = {
            "request_id": request_id,
            "normalized_prompt": normalized_prompt,
            "execution_time_ms": total_time_ms,
            "detector_count": len(self._detectors),
            "results": [r.to_dict() for r in results],
            "normalization_metadata": norm_metadata.to_dict()
        }

        try:
            self._audit_logger.log_event("PROMPT_AUDIT", request_id, details)
        except Exception as logger_error:
            # TODO: Implement logging resilience handling (e.g. local queuing database, log rotation file fallback,
            # or alerts dashboard) to prevent audit pipeline downtime from blocking the main request loop.
            pass

        return response

    def _build_error_result(
        self,
        detector: BaseDetector,
        request_id: str,
        elapsed_time_ms: float,
        error: Exception
    ) -> DetectionResult:
        """
        Constructs a standard ERROR-flagged DetectionResult representing a detector execution failure.
        """
        return DetectionResult(
            request_id=request_id,
            detector_name=detector.detector_name,
            threat_type=ThreatType.NONE,
            severity=SeverityLevel.INFORMATIONAL,
            confidence=0.0,
            matched_text="",
            evidence=f"Detector error occurred during execution: {error}",
            execution_time_ms=elapsed_time_ms,
            status=DetectionStatus.ERROR,
            timestamp=datetime.now(timezone.utc),
            metadata={"error_type": error.__class__.__name__, "message": str(error)}
        )
