"""
ITSApplication — End-to-End Transportation Domain Application Orchestrator.

Integrates the ITS Data Model and ITS Context Builder AROUND the frozen
AI-SecOps 8-stage security pipeline:
    InputValidator
    → PromptBuilder
    → PromptFirewall (including ITSTransportationThreatDetector)
    → RiskEngine
    → PolicyEngine
    → PromptHardener
    → LLMProvider
    → OutputGuard

All requests and stage lifecycle events are persisted to PostgreSQL using the
existing DatabaseAuditLogger and AuditRepository infrastructure.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, Optional

from database import AuditRepository, DatabaseAuditLogger, PostgresConnectionManager
from its.context.context_builder import ITSContextBuilder
from its.loaders.base_loader import BaseITSDataLoader
from its.loaders.json_loader import JSONMockDataLoader
from its.models.its_models import ITSContext, ITSResponse
from its.security.its_detector import ITSTransportationThreatDetector
from pipeline import (
    AISecOpsPipeline,
    AISecOpsPipelineBuilder,
    PipelineRequest,
    PipelineResponse,
)
from security.audit_logger import AuditLogger
from security.base_detector import BaseDetector
from security.detectors import (
    DelimiterEscapeDetector,
    EncodingDetector,
    JailbreakDetector,
    PromptInjectionDetector,
    SecretExtractionDetector,
    ToolAbuseDetector,
    UnicodeDetector,
)
from security.normalizer import TextNormalizer
from security.prompt_firewall import PromptFirewall

logger = logging.getLogger("its_application")


def build_its_pipeline(
    audit_logger: Optional[AuditLogger] = None,
    db_manager: Optional[PostgresConnectionManager] = None,
    fail_secure: bool = True,
) -> AISecOpsPipeline:
    """
    Builds the AI-SecOps pipeline wired with all 7 V1 security detectors,
    the ITSTransportationThreatDetector, and PostgreSQL audit persistence.

    Does NOT modify, weaken, or bypass any of the frozen 8 pipeline stages.
    """
    # Initialize PostgreSQL Audit Logging if not injected
    if audit_logger is None:
        try:
            db = db_manager or PostgresConnectionManager()
            db.initialize()
            repo = AuditRepository(db)
            audit_logger = DatabaseAuditLogger(repository=repo)
        except Exception as exc:
            logger.warning(f"Could not connect to PostgreSQL audit DB, using fallback: {exc}")
            from pipeline.pipeline import NullAuditLogger
            audit_logger = NullAuditLogger()

    normalizer = TextNormalizer()

    # All 7 V1 Security Detectors + V2 Transportation Threat Detector
    detectors: list[BaseDetector] = [
        PromptInjectionDetector(),
        JailbreakDetector(),
        UnicodeDetector(),
        EncodingDetector(),
        SecretExtractionDetector(),
        DelimiterEscapeDetector(),
        ToolAbuseDetector(),
        ITSTransportationThreatDetector(),
    ]

    firewall = PromptFirewall(
        detectors=detectors,
        audit_logger=audit_logger,
        normalizer=normalizer,
        fail_secure=fail_secure,
    )

    return (
        AISecOpsPipelineBuilder()
        .with_prompt_firewall(firewall)
        .with_audit_logger(audit_logger)
        .build()
    )


class ITSApplication:
    """
    Transportation Domain Application facade coordinating ITS context assembly,
    AI-SecOps pipeline execution, and unified PostgreSQL audit trace generation.
    """

    def __init__(
        self,
        pipeline: Optional[AISecOpsPipeline] = None,
        context_builder: Optional[ITSContextBuilder] = None,
        audit_logger: Optional[AuditLogger] = None,
        loader: Optional[BaseITSDataLoader] = None,
    ) -> None:
        self._audit_logger = audit_logger
        self._loader = loader or JSONMockDataLoader()
        self._context_builder = context_builder or ITSContextBuilder(loader=self._loader)
        self._pipeline = pipeline or build_its_pipeline(audit_logger=self._audit_logger)

        # Cache reference to pipeline audit logger
        if hasattr(self._pipeline, "_audit_logger") and self._audit_logger is None:
            self._audit_logger = self._pipeline._audit_logger

    @property
    def pipeline(self) -> AISecOpsPipeline:
        """Returns the wrapped frozen AI-SecOps pipeline."""
        return self._pipeline

    @property
    def context_builder(self) -> ITSContextBuilder:
        """Returns the ITS context builder."""
        return self._context_builder

    @property
    def audit_logger(self) -> Optional[AuditLogger]:
        """Returns the audit logger."""
        return self._audit_logger

    def process_query(
        self,
        user_query: str,
        user_id: str = "its_operator",
        session_id: Optional[str] = None,
    ) -> ITSResponse:
        """
        Executes end-to-end ITS query lifecycle:
        1. Assembles domain context via ITSContextBuilder.
        2. Logs ITS query event to PostgreSQL.
        3. Invokes the frozen 8-stage AI-SecOps security pipeline.
        4. Logs completion/security decision event to PostgreSQL.
        5. Returns structured ITSResponse.

        Args:
            user_query: User's transportation inquiry or command.
            user_id: Requesting operator ID.
            session_id: Optional conversation session identifier.

        Returns:
            ITSResponse containing decision, risk score, and sanitized output.
        """
        start_time = time.perf_counter()
        request_id = f"its_req_{uuid.uuid4().hex[:12]}"
        trace_id = f"trace_{uuid.uuid4().hex[:12]}"

        # 1. Domain Context Construction (ITS Layer)
        context = self._context_builder.build_context(user_query)
        if not context.road and not context.traffic:
            # Query might be network-wide or general
            context = self._context_builder.build_general_context(user_query)

        # 2. Record initial ITS audit event in PostgreSQL
        if self._audit_logger:
            try:
                self._audit_logger.log_event(
                    "ITS_QUERY_RECEIVED",
                    request_id,
                    {
                        "component": "ITSApplication",
                        "trace_id": trace_id,
                        "domain": "ITS",
                        "user_id": user_id,
                        "user_query": user_query,
                        "road_identified": context.road.road_name if context.road else None,
                        "action": "EXECUTE",
                        "status": "SUCCESS",
                        "message": f"ITS query received: {user_query}",
                    },
                )
            except Exception as exc:
                logger.warning(f"Failed to record ITS_QUERY_RECEIVED audit event: {exc}")

        # 3. Create PipelineRequest with context-enriched user prompt
        prompt_with_context = context.to_prompt_context()

        pipeline_req = PipelineRequest(
            user_prompt=prompt_with_context,
            request_id=request_id,
            user_id=user_id,
            session_id=session_id,
            metadata={
                "domain": "ITS",
                "trace_id": trace_id,
                "original_user_query": user_query,
                "its_context": context.to_dict(),
            },
        )

        # 4. Execute Frozen AI-SecOps 8-Stage Security Pipeline
        pipeline_resp: PipelineResponse = self._pipeline.execute(pipeline_req)

        # 5. Determine ITS Domain Decision
        decision = "BLOCKED" if pipeline_resp.blocked else "ALLOWED"
        if pipeline_resp.blocked:
            final_output = (
                f"[SECURITY BLOCK: {pipeline_resp.blocked_by}] "
                f"The transportation request was rejected by security policy. "
                f"Reason: {pipeline_resp.metadata.get('block_reason') or 'Policy violation.'}"
            )
        else:
            final_output = pipeline_resp.output_text

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # 6. Record final ITS audit event in PostgreSQL
        if self._audit_logger:
            try:
                self._audit_logger.log_event(
                    "ITS_RESPONSE_DISPATCHED",
                    request_id,
                    {
                        "component": "ITSApplication",
                        "trace_id": trace_id,
                        "domain": "ITS",
                        "decision": decision,
                        "blocked": pipeline_resp.blocked,
                        "blocked_by": pipeline_resp.blocked_by,
                        "risk_score": pipeline_resp.risk_score,
                        "risk_level": pipeline_resp.risk_level,
                        "action": "BLOCK" if pipeline_resp.blocked else "ALLOW",
                        "status": "BLOCKED" if pipeline_resp.blocked else "SUCCESS",
                        "execution_time_ms": elapsed_ms,
                        "message": f"ITS query resolved: {decision} by {pipeline_resp.blocked_by or 'pipeline'}",
                    },
                )
            except Exception as exc:
                logger.warning(f"Failed to record ITS_RESPONSE_DISPATCHED audit event: {exc}")

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
