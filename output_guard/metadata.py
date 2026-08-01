"""
Output metadata builder component.
"""

from __future__ import annotations

from typing import Any, Mapping


class OutputMetadataBuilder:
    """
    Builds comprehensive metadata dictionary for output guard processing.
    """

    def build_metadata(
        self,
        original_length: int,
        sanitized_length: int,
        execution_time_ms: float,
        step_results: list[dict[str, Any]],
        extra_metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Assembles telemetry dictionary.
        """
        base_meta: dict[str, Any] = {
            "original_length": original_length,
            "sanitized_length": sanitized_length,
            "length_delta": sanitized_length - original_length,
            "execution_time_ms": execution_time_ms,
            "step_results_count": len(step_results),
            "step_results": step_results,
        }
        if extra_metadata:
            base_meta.update(extra_metadata)
        return base_meta
