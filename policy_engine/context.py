"""
RiskContext Domain Model for the Policy Engine.

Captures input context including request details, original prompt text, risk score,
detected threats, and evidence findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from policy_engine.exceptions import InvalidPolicyInputError


@dataclass(slots=True, frozen=True)
class RiskContext:
    """
    Input payload for policy evaluation.

    Attributes:
        request_id: Unique request identifier.
        original_prompt: Raw user or system prompt string.
        risk_score: Risk score numeric value (supports 0-100 scale or 0.0-1.0 scale).
        detected_threats: Tuple of string threat identifiers (e.g. 'credential_leak', 'secret_exposure').
        confidence_score: Confidence metric [0.0, 1.0].
        risk_level: Risk level classification ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        recommended_action: Action recommended by upstream risk engine.
        evidence: Tuple of evidence items or findings attached to assessment.
        metadata: Additional request metadata dictionary.
    """

    request_id: str
    original_prompt: str
    risk_score: float = 0.0
    detected_threats: tuple[str, ...] = field(default_factory=tuple)
    confidence_score: float = 1.0
    risk_level: str = "LOW"
    recommended_action: str = "ALLOW"
    evidence: tuple[Any, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates score ranges and tuple conversion."""
        if not isinstance(self.risk_score, (int, float)) or self.risk_score < 0:
            raise InvalidPolicyInputError(
                f"risk_score must be non-negative numeric, got {self.risk_score}"
            )

        # Convert list of detected_threats to immutable tuple
        if not isinstance(self.detected_threats, tuple):
            object.__setattr__(self, "detected_threats", tuple(self.detected_threats))

        # Convert evidence list to immutable tuple
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def score_100(self) -> float:
        """
        Returns normalized risk score on a 0-100 scale.

        If input risk_score is <= 1.0, scales it by 100.0. Otherwise returns risk_score.
        """
        if self.risk_score <= 1.0 and self.risk_score > 0.0:
            return self.risk_score * 100.0
        return float(self.risk_score)

    @property
    def composite_score(self) -> float:
        """
        Returns normalized risk score on a 0.0-1.0 scale.
        """
        return self.score_100 / 100.0

    @classmethod
    def from_risk_response(
        cls,
        request_id: str,
        original_prompt: str,
        risk_response: Any,
        metadata: dict[str, Any] | None = None,
    ) -> RiskContext:
        """
        Factory helper creating a RiskContext directly from a RiskEngineResponse,
        RiskAssessment, or dictionary payload.
        """
        combined_meta = dict(metadata or {})
        detected: list[str] = []

        if hasattr(risk_response, "assessment"):
            assessment = risk_response.assessment
            recommendation = getattr(risk_response, "recommendation", None)
            rec_action_obj = getattr(recommendation, "action", "ALLOW") if recommendation is not None else "ALLOW"
            rec_action = (
                rec_action_obj.value
                if isinstance(rec_action_obj, Enum)
                else str(rec_action_obj)
            )
            risk_lvl = (
                assessment.risk_level.value
                if isinstance(assessment.risk_level, Enum)
                else str(assessment.risk_level)
            )

            # Extract threat types from evidence items
            ev_list = tuple(assessment.evidence)
            for item in ev_list:
                ftype = getattr(item, "finding_type", None)
                if ftype:
                    detected.append(str(ftype).lower())

            return cls(
                request_id=request_id,
                original_prompt=original_prompt,
                risk_score=assessment.composite_score,
                detected_threats=tuple(detected),
                confidence_score=assessment.confidence_score,
                risk_level=risk_lvl,
                recommended_action=rec_action,
                evidence=ev_list,
                metadata={**combined_meta, **dict(assessment.metadata)},
            )
        elif hasattr(risk_response, "composite_score"):
            # Direct RiskAssessment object
            rec_action = str(getattr(risk_response, "recommended_action", "ALLOW"))
            risk_lvl = (
                risk_response.risk_level.value
                if isinstance(risk_response.risk_level, Enum)
                else str(risk_response.risk_level)
            )
            ev_list = tuple(getattr(risk_response, "evidence", ()))
            for item in ev_list:
                ftype = getattr(item, "finding_type", None)
                if ftype:
                    detected.append(str(ftype).lower())

            return cls(
                request_id=request_id,
                original_prompt=original_prompt,
                risk_score=risk_response.composite_score,
                detected_threats=tuple(detected),
                confidence_score=risk_response.confidence_score,
                risk_level=risk_lvl,
                recommended_action=rec_action,
                evidence=ev_list,
                metadata={**combined_meta, **dict(getattr(risk_response, "metadata", {}))},
            )
        elif isinstance(risk_response, dict):
            raw_score = risk_response.get("risk_score")
            if raw_score is None:
                raw_score = risk_response.get("composite_score", 0.0)
            score_val = 0.0 if raw_score is None else float(raw_score)

            raw_confidence = risk_response.get("confidence_score")
            conf_val = 1.0 if raw_confidence is None else float(raw_confidence)

            raw_threats = risk_response.get("detected_threats", ())
            threats_val = () if raw_threats is None else tuple(raw_threats)

            raw_level = risk_response.get("risk_level", "LOW")
            level_val = "LOW" if raw_level is None else str(raw_level)

            raw_action = risk_response.get("recommended_action", "ALLOW")
            action_val = "ALLOW" if raw_action is None else str(raw_action)

            raw_meta = risk_response.get("metadata", {})
            meta_val = dict(raw_meta) if isinstance(raw_meta, (dict, Mapping)) else {}

            return cls(
                request_id=request_id,
                original_prompt=original_prompt,
                risk_score=score_val,
                detected_threats=threats_val,
                confidence_score=conf_val,
                risk_level=level_val,
                recommended_action=action_val,
                metadata={**combined_meta, **meta_val},
            )
        else:
            raise InvalidPolicyInputError(
                f"Unsupported risk_response payload type: {type(risk_response)}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes RiskContext to dictionary."""
        return {
            "request_id": self.request_id,
            "original_prompt": self.original_prompt,
            "risk_score": self.risk_score,
            "score_100": self.score_100,
            "composite_score": self.composite_score,
            "detected_threats": list(self.detected_threats),
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level,
            "recommended_action": self.recommended_action,
            "evidence_count": len(self.evidence),
            "metadata": dict(self.metadata),
        }
