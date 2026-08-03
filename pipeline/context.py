"""
PipelineContext for state tracking across AISecOpsPipeline execution stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pipeline.request import PipelineRequest


@dataclass(slots=True)
class PipelineContext:
    """
    Mutable context container tracking state and intermediate DTOs during pipeline execution.

    Created at pipeline invocation and discarded after final response assembly.
    """

    request: PipelineRequest
    request_id: str
    start_time: float = field(default_factory=time.perf_counter)
    
    # Stage Outputs
    draft_prompt: str = ""
    validation_response: Any = None
    firewall_response: Any = None
    risk_assessment: Any = None
    risk_context: Any = None
    policy_decision: Any = None
    hardening_result: Any = None
    hardened_prompt: str = ""
    raw_llm_output: str = ""
    output_guard_result: Any = None
    final_output_text: str = ""

    # Telemetry and Execution Tracking
    stage_timings_ms: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # State flags
    is_blocked: bool = False
    blocked_by: Optional[str] = None
    block_reason: str = ""
    fail_secure_triggered: bool = False

    def record_stage_timing(self, stage_name: str, elapsed_ms: float) -> None:
        """Records execution duration for a pipeline stage in milliseconds."""
        self.stage_timings_ms[stage_name] = round(elapsed_ms, 3)

    def add_warning(self, warning_message: str) -> None:
        """Appends a non-fatal warning message."""
        if warning_message and warning_message not in self.warnings:
            self.warnings.append(warning_message)

    def total_elapsed_ms(self) -> float:
        """Returns total elapsed wall-clock time in milliseconds since context initialization."""
        return round((time.perf_counter() - self.start_time) * 1000.0, 3)
