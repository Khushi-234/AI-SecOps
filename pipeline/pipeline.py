"""
AISecOpsPipeline — Central Orchestrator for AI-SecOps Framework v1.0.

Coordinates all 8 frozen modules in a strict fail-secure sequence:
1. Input Validator
2. Prompt Builder
3. Prompt Firewall
4. Risk Engine
5. Policy Engine
6. Prompt Hardener
7. LLM Provider
8. Output Guard
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Union

from input_validator.input_validator import InputValidator
from llm.base_provider import BaseLLMProvider
from llm.prompt_builder import PromptBuilder
from output_guard.enums import OutputAction
from output_guard.facade import OutputGuardFacade
from pipeline.config import PipelineConfig
from pipeline.context import PipelineContext
from pipeline.exceptions import (
    FailSecurePipelineError,
    PipelineConfigurationError,
    PipelineError,
)
from pipeline.logger import PipelineLogger
from pipeline.request import PipelineRequest
from pipeline.response import PipelineResponse, PipelineStatus
from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.engine import PolicyEngine
from prompt_hardener.hardener import PromptHardener
from risk_engine.engine import RiskEngine
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import InvalidRiskInputError
from risk_engine.models import RiskAssessment
from risk_engine.policy_mapper import PolicyMapper
from risk_engine.scoring.adaptive import AdaptiveScorer
from risk_engine.scoring.composite import CompositeScorer
from risk_engine.scoring.threshold import ThresholdScorer
from risk_engine.scoring.weighted import WeightedScorer
from security.audit_logger import AuditLogger
from security.normalizer import TextNormalizer
from security.prompt_firewall import PromptFirewall


class NullAuditLogger(AuditLogger):
    """Fallback silent AuditLogger for PromptFirewall default initialization."""

    def log_event(
        self, event_type: str, request_id: str, details: dict[str, Any]
    ) -> None:
        pass


class AISecOpsPipeline:
    """
    Enterprise Orchestrator for AI-SecOps Framework runtime.

    Implements zero-business-logic orchestration over frozen security facades.
    """

    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        input_validator: Optional[InputValidator] = None,
        prompt_builder: Optional[PromptBuilder] = None,
        prompt_firewall: Optional[PromptFirewall] = None,
        risk_engine: Optional[RiskEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
        prompt_hardener: Optional[PromptHardener] = None,
        llm_provider: Optional[BaseLLMProvider] = None,
        output_guard: Optional[OutputGuardFacade] = None,
        logger: Optional[PipelineLogger] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initializes pipeline with injected or default component facades."""
        self._config = config or PipelineConfig()
        self._logger = logger or PipelineLogger()
        self._audit_logger = audit_logger or NullAuditLogger()

        self._input_validator = input_validator or InputValidator(
            config=self._config.input_validator_config
        )
        self._prompt_builder = prompt_builder or PromptBuilder()

        if prompt_firewall is not None:
            self._prompt_firewall = prompt_firewall
        else:
            self._prompt_firewall = PromptFirewall(
                detectors=[],
                audit_logger=self._audit_logger,
                normalizer=TextNormalizer(),
                fail_secure=self._config.fail_secure_default,
            )

        if risk_engine is not None:
            self._risk_engine = risk_engine
        else:
            w_scorer = WeightedScorer(config=self._config.risk_engine_config)
            t_scorer = ThresholdScorer(config=self._config.risk_engine_config)
            a_scorer = AdaptiveScorer(config=self._config.risk_engine_config)
            scorer = CompositeScorer(
                weighted_scorer=w_scorer,
                threshold_scorer=t_scorer,
                adaptive_scorer=a_scorer,
                config=self._config.risk_engine_config,
            )
            policy_mapper = PolicyMapper(config=self._config.risk_engine_config)
            self._risk_engine = RiskEngine(
                config=self._config.risk_engine_config,
                scorer=scorer,
                policy_mapper=policy_mapper,
            )
        self._policy_engine = policy_engine or PolicyEngine(
            config=self._config.policy_engine_config
        )
        self._prompt_hardener = prompt_hardener or PromptHardener(
            config=self._config.prompt_hardener_config
        )
        if llm_provider is not None:
            self._llm_provider = llm_provider
        else:
            try:
                from llm.groq_provider import GroqProvider
                self._llm_provider = GroqProvider()
            except ImportError:
                class DefaultFallbackProvider(BaseLLMProvider):
                    def generate_response(self, prompt: str) -> str:
                        return f"[Default Fallback] Completion for prompt: {prompt}"
                self._llm_provider = DefaultFallbackProvider()

        self._output_guard = output_guard or OutputGuardFacade(
            config=self._config.output_guard_config
        )

    @property
    def config(self) -> PipelineConfig:
        """Exposes read-only pipeline configuration."""
        return self._config

    def execute(
        self, request: Union[PipelineRequest, str]
    ) -> PipelineResponse:
        """
        Executes the end-to-end AI-SecOps security pipeline.

        Args:
            request: PipelineRequest object or prompt string.

        Returns:
            PipelineResponse containing sanitized completion or block details.
        """
        if isinstance(request, str):
            pipeline_req = PipelineRequest(user_prompt=request)
        elif isinstance(request, PipelineRequest):
            pipeline_req = request
        else:
            raise PipelineConfigurationError(
                f"Invalid request type: expected PipelineRequest or str, got {type(request)}"
            )

        context = PipelineContext(
            request=pipeline_req, request_id=pipeline_req.request_id
        )
        try:
            self._record_audit(
                "PIPELINE_EVENT",
                context.request_id,
                {
                    "component": "AISecOpsPipeline",
                    "message": "Pipeline execution started.",
                    "action": "EXECUTE",
                    "status": "SUCCESS",
                    "user_id": context.request.user_id,
                    "provider_name": context.request.provider_name,
                },
            )

            # -----------------------------------------------------------------
            # Stage 1: Input Validation
            # -----------------------------------------------------------------
            self._execute_input_validation(context)
            if context.is_blocked:
                return self._handle_early_exit(context)

            # -----------------------------------------------------------------
            # Stage 2: Prompt Building
            # -----------------------------------------------------------------
            self._execute_prompt_builder(context)

            # -----------------------------------------------------------------
            # Stage 3: Prompt Firewall Verification
            # -----------------------------------------------------------------
            self._execute_prompt_firewall(context)
            if context.is_blocked:
                return self._handle_early_exit(context)

            # -----------------------------------------------------------------
            # Stage 4: Risk Engine Evaluation
            # -----------------------------------------------------------------
            self._execute_risk_engine(context)

            # -----------------------------------------------------------------
            # Stage 5: Policy Engine Enforcement
            # -----------------------------------------------------------------
            self._execute_policy_engine(context)
            if context.is_blocked:
                return self._handle_early_exit(context)

            # -----------------------------------------------------------------
            # Stage 6: Prompt Hardener
            # -----------------------------------------------------------------
            self._execute_prompt_hardener(context)

            # -----------------------------------------------------------------
            # Stage 7: LLM Provider Execution
            # -----------------------------------------------------------------
            self._execute_llm_provider(context)

            # -----------------------------------------------------------------
            # Stage 8: Output Guard Verification & Sanitization
            # -----------------------------------------------------------------
            self._execute_output_guard(context)
            if context.is_blocked:
                return self._handle_early_exit(context)

            # -----------------------------------------------------------------
            # Stage 9: Final Response Assembly
            # -----------------------------------------------------------------
            return self._build_final_response(context)

        except PipelineError as pe:
            self._logger.error(
                f"Pipeline exception: {pe.message}",
                request_id=context.request_id,
                exc_info=True,
            )
            return self._handle_fail_secure(context, pe, stage=pe.stage or "Pipeline")
        except Exception as exc:
            self._logger.error(
                f"Unhandled unexpected failure: {exc}",
                request_id=context.request_id,
                exc_info=True,
            )
            return self._handle_fail_secure(context, exc, stage="UncaughtBoundary")

    def _record_audit(
        self, event_type: str, request_id: str, details: Dict[str, Any]
    ) -> None:
        """Safely dispatches audit event to configured audit_logger."""
        if not getattr(self._config, "enable_audit_logging", True):
            return
        try:
            self._audit_logger.log_event(event_type, request_id, details)
        except Exception as exc:
            self._logger.error(
                f"Audit logging failure for event '{event_type}': {exc}",
                request_id=request_id,
            )
            if (
                getattr(self._config, "fail_secure_on_db_error", False)
                and event_type != "FAIL_SECURE"
            ):
                raise FailSecurePipelineError(
                    f"Audit logging failed: {exc}", original_exception=exc, stage="AuditLogging"
                ) from exc

    # =========================================================================
    # Internal Stage Handlers
    # =========================================================================

    def _execute_input_validation(self, context: PipelineContext) -> None:
        stage = "InputValidator"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            val_resp = self._input_validator.validate(
                prompt=context.request.user_prompt,
                context={"request_id": context.request_id},
            )
            context.validation_response = val_resp
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )

            if not val_resp.is_valid:
                context.is_blocked = True
                context.blocked_by = stage
                err_msgs = [r.error_message for r in val_resp.results if not r.is_valid and r.error_message]
                context.block_reason = "; ".join(err_msgs) or "Input validation checks failed."
                self._logger.log_stage_block(stage, context.request_id, context.block_reason)

            self._record_audit(
                "INPUT_VALIDATION",
                context.request_id,
                {
                    "component": stage,
                    "message": context.block_reason or "Input validation passed.",
                    "action": "BLOCK" if context.is_blocked else "ALLOW",
                    "status": "BLOCKED" if context.is_blocked else "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"InputValidator failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_prompt_builder(self, context: PipelineContext) -> None:
        stage = "PromptBuilder"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            draft_prompt = self._prompt_builder.build_prompt(
                context.request.user_prompt
            )
            context.draft_prompt = draft_prompt
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )
            self._record_audit(
                "PIPELINE_EVENT",
                context.request_id,
                {
                    "component": stage,
                    "message": "Prompt building completed.",
                    "action": "ALLOW",
                    "status": "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"PromptBuilder failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_prompt_firewall(self, context: PipelineContext) -> None:
        stage = "PromptFirewall"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            firewall_resp = self._prompt_firewall.inspect_prompt(
                prompt=context.request.user_prompt,
                context={"request_id": context.request_id},
            )
            context.firewall_response = firewall_resp
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )
            self._record_audit(
                "PROMPT_FIREWALL",
                context.request_id,
                {
                    "component": stage,
                    "message": context.block_reason or "Prompt firewall verification completed.",
                    "action": "BLOCK" if context.is_blocked else "ALLOW",
                    "status": "BLOCKED" if context.is_blocked else "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"PromptFirewall failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_risk_engine(self, context: PipelineContext) -> None:
        stage = "RiskEngine"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            sources = []
            if context.validation_response:
                val_threats = [r for r in context.validation_response.results if not r.is_valid]
                if val_threats:
                    sources.append(val_threats)

            if context.firewall_response:
                fw_threats = [
                    r for r in context.firewall_response.results
                    if getattr(r.threat_type, "value", str(r.threat_type)).upper() not in ("NONE", "CLEAN")
                    or getattr(r.severity, "value", str(r.severity)).upper() not in ("INFORMATIONAL", "INFO")
                ]
                if fw_threats:
                    sources.append(fw_threats)

            if not sources:
                risk_assessment = RiskAssessment(
                    assessment_id=f"ast_{context.request_id}",
                    composite_score=0.0,
                    confidence_score=1.0,
                    risk_level=RiskLevel.LOW,
                    recommended_action=RecommendedAction.ALLOW,
                    evidence=(),
                    scores=(),
                )
            else:
                try:
                    risk_assessment = self._risk_engine.evaluate(*sources)
                except InvalidRiskInputError:
                    risk_assessment = RiskAssessment(
                        assessment_id=f"ast_{context.request_id}",
                        composite_score=0.0,
                        confidence_score=1.0,
                        risk_level=RiskLevel.LOW,
                        recommended_action=RecommendedAction.ALLOW,
                        evidence=(),
                        scores=(),
                    )

            context.risk_assessment = risk_assessment
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )
            self._record_audit(
                "RISK_ASSESSMENT",
                context.request_id,
                {
                    "component": stage,
                    "message": f"Risk assessment completed. Score: {getattr(risk_assessment, 'composite_score', 0.0)}",
                    "action": "ALLOW",
                    "status": "SUCCESS",
                    "composite_score": getattr(risk_assessment, "composite_score", 0.0),
                    "risk_level": str(getattr(risk_assessment, "risk_level", "LOW")),
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"RiskEngine failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_policy_engine(self, context: PipelineContext) -> None:
        stage = "PolicyEngine"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            risk_ctx = RiskContext.from_risk_response(
                request_id=context.request_id,
                original_prompt=context.draft_prompt or context.request.user_prompt,
                risk_response=context.risk_assessment,
                metadata={"user_id": context.request.user_id},
            )
            context.risk_context = risk_ctx

            policy_decision = self._policy_engine.evaluate(risk_ctx)
            context.policy_decision = policy_decision
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )

            action_val = getattr(policy_decision, "action", PolicyAction.ALLOW)
            action_str = (
                action_val.value if hasattr(action_val, "value") else str(action_val)
            ).upper()

            if action_str in ("DENY", "BLOCK"):
                context.is_blocked = True
                context.blocked_by = stage
                context.block_reason = (
                    getattr(policy_decision, "reason", None)
                    or f"Request blocked by PolicyEngine decision: {action_str}"
                )
                self._logger.log_stage_block(stage, context.request_id, context.block_reason)
            elif action_str == "WARN":
                context.add_warning(
                    f"PolicyEngine WARN: {getattr(policy_decision, 'reason', 'Policy warning triggered.')}"
                )

            self._record_audit(
                "POLICY_DECISION",
                context.request_id,
                {
                    "component": stage,
                    "message": context.block_reason or f"Policy evaluation completed ({action_str}).",
                    "action": "BLOCK" if context.is_blocked else "ALLOW",
                    "status": "BLOCKED" if context.is_blocked else "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"PolicyEngine failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_prompt_hardener(self, context: PipelineContext) -> None:
        stage = "PromptHardener"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            hardening_res = self._prompt_hardener.harden(
                original_prompt=context.draft_prompt or context.request.user_prompt,
                risk_context=context.risk_context,
                policy_decision=context.policy_decision,
            )
            context.hardening_result = hardening_res
            context.hardened_prompt = (
                getattr(hardening_res, "hardened_prompt", None)
                or context.draft_prompt
                or context.request.user_prompt
            )
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )
            self._record_audit(
                "PROMPT_HARDENING",
                context.request_id,
                {
                    "component": stage,
                    "message": "Prompt hardening completed.",
                    "action": "HARDEN" if context.hardened_prompt != context.draft_prompt else "ALLOW",
                    "status": "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"PromptHardener failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_llm_provider(self, context: PipelineContext) -> None:
        stage = "LLMProvider"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            prompt_to_send = context.hardened_prompt or context.draft_prompt or context.request.user_prompt
            raw_output = self._llm_provider.generate_response(prompt_to_send)
            context.raw_llm_output = raw_output or ""
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )
            self._record_audit(
                "LLM_RESPONSE",
                context.request_id,
                {
                    "component": stage,
                    "message": "LLM response generation completed.",
                    "action": "EXECUTE",
                    "status": "SUCCESS",
                    "provider_name": context.request.provider_name,
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"LLMProvider generation failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    def _execute_output_guard(self, context: PipelineContext) -> None:
        stage = "OutputGuard"
        self._logger.log_stage_start(stage, context.request_id)
        t0 = time.perf_counter()

        try:
            og_result = self._output_guard.guard_output(context.raw_llm_output)
            context.output_guard_result = og_result
            context.record_stage_timing(stage, (time.perf_counter() - t0) * 1000.0)
            self._logger.log_stage_complete(
                stage, context.request_id, context.stage_timings_ms[stage]
            )

            action_val = getattr(og_result, "action_taken", OutputAction.ALLOW)
            action_str = (
                action_val.value if hasattr(action_val, "value") else str(action_val)
            ).upper()

            if action_str in ("BLOCK", "DENY"):
                context.is_blocked = True
                context.blocked_by = stage
                context.block_reason = "LLM response blocked by Output Guard security rules."
                self._logger.log_stage_block(stage, context.request_id, context.block_reason)
            else:
                context.final_output_text = (
                    getattr(og_result, "sanitized_output", None)
                    or context.raw_llm_output
                )

            self._record_audit(
                "OUTPUT_GUARD",
                context.request_id,
                {
                    "component": stage,
                    "message": context.block_reason or "Output guard verification passed.",
                    "action": "BLOCK" if context.is_blocked else ("SANITIZE" if getattr(og_result, "applied_sanitizers", []) else "ALLOW"),
                    "status": "BLOCKED" if context.is_blocked else "SUCCESS",
                    "elapsed_ms": context.stage_timings_ms.get(stage, 0.0),
                },
            )
        except Exception as exc:
            if self._config.fail_secure_default:
                raise FailSecurePipelineError(
                    f"OutputGuard failed: {exc}", original_exception=exc, stage=stage
                ) from exc
            raise

    # =========================================================================
    # Early Exit, Fail-Secure, and Response Builders
    # =========================================================================

    def _handle_early_exit(self, context: PipelineContext) -> PipelineResponse:
        """Handles early termination due to guardrail blocks or security policy rules."""
        total_time = context.total_elapsed_ms()
        risk_score = 0.0
        risk_level = "LOW"

        if context.risk_assessment:
            risk_score = getattr(context.risk_assessment, "composite_score", 0.0)
            risk_level_obj = getattr(context.risk_assessment, "risk_level", "LOW")
            risk_level = (
                risk_level_obj.value
                if hasattr(risk_level_obj, "value")
                else str(risk_level_obj)
            )

        self._logger.warning(
            f"Pipeline terminated early. Blocked by: {context.blocked_by}. Reason: {context.block_reason}",
            request_id=context.request_id,
        )

        self._record_audit(
            "PIPELINE_EVENT",
            context.request_id,
            {
                "component": "AISecOpsPipeline",
                "message": f"Pipeline early exit blocked by {context.blocked_by}: {context.block_reason}",
                "action": "BLOCK",
                "status": "BLOCKED",
                "blocked_by": context.blocked_by,
                "block_reason": context.block_reason,
            },
        )

        return PipelineResponse(
            request_id=context.request_id,
            status=PipelineStatus.BLOCKED,
            success=False,
            blocked=True,
            blocked_by=context.blocked_by,
            output_text=f"[BLOCKED] Request halted by {context.blocked_by}: {context.block_reason}",
            risk_score=risk_score,
            risk_level=risk_level,
            warnings=list(context.warnings),
            total_execution_time_ms=total_time,
            stage_timings_ms=dict(context.stage_timings_ms),
            metadata={"block_reason": context.block_reason, "early_exit": True},
        )

    def _handle_fail_secure(
        self,
        context: PipelineContext,
        error: Exception,
        stage: str = "Unknown",
    ) -> PipelineResponse:
        """Handles fail-secure fallback when unhandled runtime errors occur."""
        total_time = context.total_elapsed_ms()
        self._logger.error(
            f"Fail-Secure boundary invoked at stage '{stage}'. Execution halted safely.",
            request_id=context.request_id,
        )

        self._record_audit(
            "FAIL_SECURE",
            context.request_id,
            {
                "component": stage,
                "message": f"Fail-secure boundary invoked at stage '{stage}': {error}",
                "action": "FAIL_SECURE",
                "status": "FAIL_SECURE",
                "severity": "CRITICAL",
                "failed_stage": stage,
                "error": str(error),
            },
        )

        return PipelineResponse(
            request_id=context.request_id,
            status=PipelineStatus.FAIL_SECURE_BLOCKED,
            success=False,
            blocked=True,
            blocked_by=stage,
            output_text="[FAIL-SECURE] Request blocked due to a framework security constraint or internal component failure.",
            risk_score=1.0,
            risk_level="CRITICAL",
            warnings=list(context.warnings),
            total_execution_time_ms=total_time,
            stage_timings_ms=dict(context.stage_timings_ms),
            metadata={"fail_secure": True, "failed_stage": stage, "error": str(error)},
        )

    def _build_final_response(self, context: PipelineContext) -> PipelineResponse:
        """Assembles the final PipelineResponse for successful executions."""
        total_time = context.total_elapsed_ms()
        risk_score = 0.0
        risk_level = "LOW"

        if context.risk_assessment:
            risk_score = getattr(context.risk_assessment, "composite_score", 0.0)
            risk_level_obj = getattr(context.risk_assessment, "risk_level", "LOW")
            risk_level = (
                risk_level_obj.value
                if hasattr(risk_level_obj, "value")
                else str(risk_level_obj)
            )

        hardening_applied = []
        if context.hardening_result:
            hardening_applied = list(
                getattr(context.hardening_result, "applied_injectors", [])
            )

        sanitization_applied = []
        if context.output_guard_result:
            sanitization_applied = list(
                getattr(context.output_guard_result, "applied_sanitizers", [])
            )

        self._logger.info(
            f"Pipeline completed successfully in {total_time:.2f} ms.",
            request_id=context.request_id,
        )

        self._record_audit(
            "PIPELINE_EVENT",
            context.request_id,
            {
                "component": "AISecOpsPipeline",
                "message": f"Pipeline execution completed successfully in {total_time:.2f} ms.",
                "action": "ALLOW",
                "status": "SUCCESS",
                "total_execution_time_ms": total_time,
                "risk_score": risk_score,
            },
        )

        return PipelineResponse(
            request_id=context.request_id,
            status=PipelineStatus.SUCCESS,
            success=True,
            blocked=False,
            blocked_by=None,
            output_text=context.final_output_text or context.raw_llm_output,
            risk_score=risk_score,
            risk_level=risk_level,
            warnings=list(context.warnings),
            applied_hardening=hardening_applied,
            applied_sanitization=sanitization_applied,
            total_execution_time_ms=total_time,
            stage_timings_ms=dict(context.stage_timings_ms),
            metadata={
                "has_hardening": len(hardening_applied) > 0,
                "has_sanitization": len(sanitization_applied) > 0,
            },
        )
