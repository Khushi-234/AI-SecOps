"""
Tests for Fail-Secure exception handling and component isolation in AISecOpsPipeline.
"""

import pytest
from unittest.mock import MagicMock

from pipeline import (
    AISecOpsPipeline,
    AISecOpsPipelineBuilder,
    PipelineStatus,
)


def test_fail_secure_on_component_exception():
    """Verifies that an unhandled exception in PromptFirewall invokes fail-secure exit."""
    mock_firewall = MagicMock()
    mock_firewall.inspect_prompt.side_effect = RuntimeError("Firewall database connection crashed")

    pipeline = (
        AISecOpsPipelineBuilder()
        .with_prompt_firewall(mock_firewall)
        .build()
    )

    response = pipeline.execute("Test prompt")

    assert response.status == PipelineStatus.FAIL_SECURE_BLOCKED
    assert response.success is False
    assert response.blocked is True
    assert response.blocked_by == "PromptFirewall"
    assert response.risk_score == 1.0
    assert response.risk_level == "CRITICAL"
    assert "[FAIL-SECURE]" in response.output_text
    assert response.metadata["fail_secure"] is True


def test_fail_secure_on_llm_provider_failure():
    """Verifies that an unhandled LLM API error is caught by fail-secure boundary."""
    mock_provider = MagicMock()
    mock_provider.generate_response.side_effect = TimeoutError("LLM API timed out")

    pipeline = (
        AISecOpsPipelineBuilder()
        .with_llm_provider(mock_provider)
        .build()
    )

    response = pipeline.execute("Test LLM timeout")

    assert response.status == PipelineStatus.FAIL_SECURE_BLOCKED
    assert response.success is False
    assert response.blocked is True
    assert response.blocked_by == "LLMProvider"
    assert "[FAIL-SECURE]" in response.output_text
    assert "LLMProvider" in response.metadata["failed_stage"]
