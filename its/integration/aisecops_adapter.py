"""
AISecOpsAdapter — Integration Adapter connecting ITS Domain Layer to Frozen AI-SecOps Pipeline.

Responsibilities:
1. Accept an ITS user query.
2. Call the existing ITS Context Builder.
3. Obtain the relevant ITS domain context.
4. Convert that information into the format expected by the existing AI-SecOps pipeline (PipelineRequest).
5. Call the EXISTING AISecOpsPipeline.
6. Return the pipeline response.

The adapter does NOT:
- Implement security detection (delegated to PromptFirewall)
- Calculate risk (delegated to RiskEngine)
- Make policy decisions (delegated to PolicyEngine)
- Call the LLM directly or call LLMProvider directly
- Bypass Prompt Firewall, Risk Engine, Policy Engine, or Output Guard
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from its.application import build_its_pipeline
from its.context.context_builder import ITSContextBuilder
from its.models.its_models import ITSContext, ITSResponse
from pipeline import AISecOpsPipeline, PipelineRequest, PipelineResponse
from security.audit_logger import AuditLogger


class AISecOpsAdapter:
    """
    Domain adapter bridging the ITS application layer to the frozen AI-SecOps security pipeline.
    """

    def __init__(
        self,
        pipeline: Optional[AISecOpsPipeline] = None,
        context_builder: Optional[ITSContextBuilder] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """
        Initializes the adapter with the security pipeline and ITS context builder.

        Args:
            pipeline: Existing AISecOpsPipeline instance. If None, built via build_its_pipeline().
            context_builder: Existing ITSContextBuilder instance. If None, default instance created.
            audit_logger: Optional custom AuditLogger.
        """
        self._context_builder = context_builder or ITSContextBuilder()
        self._pipeline = pipeline or build_its_pipeline(audit_logger=audit_logger)

    @property
    def pipeline(self) -> AISecOpsPipeline:
        """Returns the wrapped frozen AI-SecOps pipeline."""
        return self._pipeline

    @property
    def context_builder(self) -> ITSContextBuilder:
        """Returns the wrapped ITS context builder."""
        return self._context_builder

    def execute_query(
        self,
        user_query: str,
        user_id: str = "its_operator",
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResponse:
        """
        Executes an ITS query through the complete 8-stage AI-SecOps security pipeline.

        1. Calls ITSContextBuilder to assemble domain telemetry context.
        2. Wraps the context into a PipelineRequest.
        3. Invokes AISecOpsPipeline.execute(request).
        4. Returns the resulting PipelineResponse.

        Args:
            user_query: Raw natural language transportation query.
            user_id: Requesting operator ID.
            session_id: Optional conversation session identifier.
            metadata: Optional additional metadata dict.

        Returns:
            PipelineResponse produced by AISecOpsPipeline.
        """
        # Step 1 & 2: Assembles ITS Domain Context
        context = self._context_builder.build_context(user_query)
        if not context.road and not context.traffic:
            context = self._context_builder.build_general_context(user_query)

        # Step 3: Format domain context text
        prompt_with_context = context.to_prompt_context()

        request_id = f"its_req_{uuid.uuid4().hex[:12]}"
        trace_id = f"trace_{uuid.uuid4().hex[:12]}"

        req_metadata: Dict[str, Any] = {
            "domain": "ITS",
            "trace_id": trace_id,
            "original_user_query": user_query,
            "its_context": context.to_dict(),
        }
        if metadata:
            req_metadata.update(metadata)

        # Step 4: Create standard PipelineRequest
        pipeline_req = PipelineRequest(
            user_prompt=prompt_with_context,
            request_id=request_id,
            user_id=user_id,
            session_id=session_id,
            metadata=req_metadata,
        )

        # Step 5 & 6: Execute frozen 8-stage AI-SecOps Pipeline
        return self._pipeline.execute(pipeline_req)

    def process_query(
        self,
        user_query: str,
        user_id: str = "its_operator",
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ITSResponse:
        """
        Higher-level ITS convenience method returning a structured ITSResponse DTO
        containing both domain telemetry context and security decision telemetry.

        Args:
            user_query: Raw natural language transportation query.
            user_id: Requesting operator ID.
            session_id: Optional conversation session identifier.
            metadata: Optional additional metadata dict.

        Returns:
            ITSResponse DTO.
        """
        t0 = time.perf_counter()
        request_id = f"its_req_{uuid.uuid4().hex[:12]}"
        trace_id = f"trace_{uuid.uuid4().hex[:12]}"

        # Assemble domain context
        context = self._context_builder.build_context(user_query)
        if not context.road and not context.traffic:
            context = self._context_builder.build_general_context(user_query)

        prompt_with_context = context.to_prompt_context()

        req_metadata: Dict[str, Any] = {
            "domain": "ITS",
            "trace_id": trace_id,
            "original_user_query": user_query,
            "its_context": context.to_dict(),
        }
        if metadata:
            req_metadata.update(metadata)

        pipeline_req = PipelineRequest(
            user_prompt=prompt_with_context,
            request_id=request_id,
            user_id=user_id,
            session_id=session_id,
            metadata=req_metadata,
        )

        # Execute frozen pipeline
        pipeline_resp = self._pipeline.execute(pipeline_req)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        decision = "BLOCKED" if pipeline_resp.blocked else "ALLOWED"
        if pipeline_resp.blocked:
            final_output = (
                f"[SECURITY BLOCK: {pipeline_resp.blocked_by}] "
                f"The transportation request was rejected by security policy. "
                f"Reason: {pipeline_resp.metadata.get('block_reason') or 'Policy violation.'}"
            )
        else:
            final_output = pipeline_resp.output_text

        return ITSResponse(
            request_id=request_id,
            trace_id=trace_id,
            user_query=user_query,
            its_context=context,
            pipeline_response=pipeline_resp,
            decision=decision,
            blocked=pipeline_resp.blocked,
            blocked_by=pipeline_resp.blocked_by,
            risk_score=pipeline_resp.risk_score,
            risk_level=pipeline_resp.risk_level,
            final_output=final_output,
            execution_time_ms=elapsed_ms,
            metadata={
                "domain": "ITS",
                "stage_timings_ms": dict(pipeline_resp.stage_timings_ms),
                "warnings": list(pipeline_resp.warnings),
                "applied_hardening": list(pipeline_resp.applied_hardening),
            },
        )
