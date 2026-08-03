"""
Unit and Integration Tests for AISecOpsPipeline runtime orchestration.
"""

import pytest
from unittest.mock import MagicMock

from llm.base_provider import BaseLLMProvider
from pipeline import (
    AISecOpsPipeline,
    AISecOpsPipelineBuilder,
    PipelineRequest,
    PipelineResponse,
    PipelineStatus,
)
from policy_engine.actions import PolicyAction
from policy_engine.models import PolicyDecision
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.models import RiskAssessment, RiskScore


class MockLLMProvider(BaseLLMProvider):
    """Mock provider for testing pipeline generation."""

    def __init__(self, response_text: str = "Mocked LLM completion response.") -> None:
        self.response_text = response_text
        self.call_count = 0
        self.last_prompt = ""

    def generate_response(self, prompt: str) -> str:
        self.call_count += 1
        self.last_prompt = prompt
        return self.response_text


def test_pipeline_successful_execution():
    """Verifies end-to-end pipeline execution with mocked LLM provider."""
    mock_provider = MockLLMProvider("Hello from security pipeline!")
    pipeline = AISecOpsPipelineBuilder().with_llm_provider(mock_provider).build()

    request = PipelineRequest(
        user_prompt="Explain security risk analysis.",
        user_id="user_123",
    )

    response = pipeline.execute(request)

    assert isinstance(response, PipelineResponse)
    assert response.status == PipelineStatus.SUCCESS
    assert response.success is True
    assert response.blocked is False
    assert response.blocked_by is None
    assert response.output_text == "Hello from security pipeline!"
    assert response.request_id == request.request_id
    assert mock_provider.call_count == 1
    assert "Explain security risk analysis." in mock_provider.last_prompt
    assert response.total_execution_time_ms > 0
    assert "InputValidator" in response.stage_timings_ms
    assert "PromptBuilder" in response.stage_timings_ms
    assert "LLMProvider" in response.stage_timings_ms
    assert "OutputGuard" in response.stage_timings_ms


def test_pipeline_execution_with_string_prompt():
    """Verifies that pipeline accepts raw string prompt inputs."""
    mock_provider = MockLLMProvider("String input processed successfully.")
    pipeline = AISecOpsPipeline(llm_provider=mock_provider)

    response = pipeline.execute("Direct string query")

    assert response.success is True
    assert response.output_text == "String input processed successfully."
    assert response.request_id.startswith("req_")


def test_pipeline_builder_injection():
    """Verifies that AISecOpsPipelineBuilder correctly injects custom dependencies."""
    mock_provider = MockLLMProvider("Custom builder response")
    mock_policy_engine = MagicMock()
    mock_policy_decision = PolicyDecision(
        action=PolicyAction.ALLOW,
        reason="Mock policy allowed request",
        rule_triggered="MockRule",
    )
    mock_policy_engine.evaluate.return_value = mock_policy_decision

    pipeline = (
        AISecOpsPipelineBuilder()
        .with_llm_provider(mock_provider)
        .with_policy_engine(mock_policy_engine)
        .build()
    )

    response = pipeline.execute("Builder test prompt")

    assert response.success is True
    assert response.output_text == "Custom builder response"
    assert mock_policy_engine.evaluate.called
