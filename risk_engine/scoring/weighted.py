from __future__ import annotations
import math
from typing import Iterable

from risk_engine.base_scorer import BaseScorer
from risk_engine.models import RiskEvidence

class WeightedScorer(BaseScorer):
    """
    Enterprise-grade weighted risk scoring algorithm implementation.

    Inherits from BaseScorer to leverage shared validation, normalization, 
    and telemetry capabilities while implementing the weighted scoring algorithm.

    Responsibilities:
    - Computes composite risk score using evidence weights and risk scores
    - Maintains evidence integrity and thread safety
    - Ensures numerical stability in calculations

    Algorithm:
    Composite Score = Σ(evidence.risk_score × evidence.weight)

    Design Principles:
    - SOLID (Single Responsibility Principle)
    - DRY (Delegates validation to BaseScorer)
    - Strategy Pattern (Scoring algorithm implementation)
    - Secure-by-Design (Immutable evidence handling)

    OWASP Alignment:
    - Explainability: Clear scoring methodology
    - Auditability: Deterministic calculations
    - Traceability: Evidence preservation
    - Security: No input mutation

    Complexity:
    - Time: O(n) linear to evidence count
    - Space: O(1) constant additional memory

    Thread Safety:
    - Stateless implementation
    - No shared mutable state
    - Pure function design

    Security Considerations:
    - Never mutates input evidence
    - No dynamic code execution
    - Preserves evidence integrity
    - Validates via base class
    """

    def _score(self, evidence: Iterable[RiskEvidence]) -> float:
        """
        Computes weighted composite risk score from validated evidence.

        Args:
            evidence: Iterable of validated RiskEvidence objects

        Returns:
            float: Raw composite risk score before normalization

        Implementation:
        1. Computes weighted sum using stable floating-point accumulation
        2. Preserves evidence integrity (no mutation)
        3. Handles empty evidence case safely
        """
        return self._compute_weighted_sum(evidence)

    def _compute_weighted_sum(self, evidence: Iterable[RiskEvidence]) -> float:
        """
        Computes numerically stable weighted sum of risk scores.

        Uses pairwise summation to minimize floating-point errors.

        Args:
            evidence: Iterable of RiskEvidence objects

        Returns:
            float: Σ(risk_score × weight)
        """
        # Using math.fsum for stable floating-point summation
        return math.fsum(
            evidence_item.risk_score * float(getattr(evidence_item, "weight", 1.0))
            for evidence_item in evidence
        )