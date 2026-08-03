"""
PipelineRequest DTO for AI-SecOps Framework pipeline execution.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(slots=True, frozen=True)
class PipelineRequest:
    """
    Input request DTO passed into AISecOpsPipeline.execute().

    Attributes:
        user_prompt: Raw user input prompt string.
        request_id: Unique correlation identifier. Auto-generated if not provided.
        user_id: Identifier of the invoking user.
        session_id: Conversation session identifier.
        provider_name: Selected LLM provider name (e.g., 'groq', 'openai').
        metadata: Additional contextual key-value pairs.
    """

    user_prompt: str
    request_id: str = field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    provider_name: str = "groq"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates input payload basic constraints."""
        if self.user_prompt is None or not isinstance(self.user_prompt, str):
            raise ValueError("PipelineRequest user_prompt must be a non-null string.")
        if not self.request_id:
            object.__setattr__(self, "request_id", f"req_{uuid.uuid4().hex[:12]}")
