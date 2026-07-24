from __future__ import annotations
import math
from typing import Iterable

from risk_engine.scoring.base_scorer import BaseScorer
from risk_engine.models import RiskEvidence
from risk_engine.enums import RiskLevel

class ThresholdScorer(BaseScorer):
    """
    Enterprise-grade threshold-based risk scoring strategy implementation.

    Inherits from BaseScorer to leverage shared validation, normalization, 
    and telemetry capabilities while implementing threshold-based scoring.

    Responsibilities:
    - Evaluates risk evidence against configurable thresholds
    - Computes composite score based on threshold classifications
    - Maintains evidence integrity and thread safety

    Algorithm:
    For each RiskEvidence item:
        score < LOW_THRESHOLD → LOW contribution (config.threshold_contributions[RiskLevel.LOW])
        LOW_THRESHOLD ≤ score < MEDIUM_THRESHOLD → MEDIUM contribution (config.threshold_contributions[RiskLevel.MEDIUM])
        MEDIUM_THRESHOLD ≤ score < HIGH_THRESHOLD → HIGH contribution (config.threshold_contributions[RiskLevel.HIGH])
        score ≥ HIGH_THRESHOLD → CRITICAL contribution (config.threshold_contributions[RiskLevel.CRITICAL])
    Composite Score = Σ(contribution_values)

    Design Principles:
    - SOLID (Strategy Pattern implementation)
    - DRY (Delegates validation to BaseScorer)
    - Secure-by-Design (Immutable evidence handling)
    - Separation of Concerns (Pure scoring logic)

    OWASP Alignment:
    - Explainability: Clear threshold classification
    - Auditability: Deterministic threshold mapping
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
        Computes threshold-based composite risk score from validated evidence.

        Args:
            evidence: Iterable of validated RiskEvidence objects

        Returns:
            float: Raw composite risk score before normalization

        Implementation:
        1. Classifies each evidence item into threshold categories
        2. Sums contributions based on configured values
        3. Preserves evidence integrity (no mutation)
        """
        return self._compute_threshold_sum(evidence)

    def _classify_evidence(self, risk_score: float) -> RiskLevel:
        """
        Classifies risk score into threshold category based on configured values.

        Args:
            risk_score: Individual evidence risk score

        Returns:
            RiskLevel: Threshold category enum value

        Configuration:
        - Uses thresholds from RiskEngineConfig:
          self.config.thresholds.low
          self.config.thresholds.medium
          self.config.thresholds.high
        """
        thresholds = self.config.thresholds
        if risk_score < thresholds.low:
            return RiskLevel.LOW
        if risk_score < thresholds.medium:
            return RiskLevel.MEDIUM
        if risk_score < thresholds.high:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def _get_contribution_value(self, category: RiskLevel) -> float:
        """
        Gets configured contribution value for a threshold category.

        Args:
            category: RiskLevel enum value

        Returns:
            float: Contribution value from configuration

        Configuration:
        - Uses contribution values from RiskEngineConfig:
          self.config.threshold_contributions dictionary
        """
        return self.config.threshold_contributions[category]

    def _compute_threshold_sum(self, evidence: Iterable[RiskEvidence]) -> float:
        """
        Computes composite score using numerically stable floating-point accumulation.

        Args:
            evidence: Iterable of RiskEvidence objects

        Returns:
            float: Numerically stable sum of threshold contributions

        Implementation:
        - Uses math.fsum for deterministic floating-point summation
        - Avoids manual accumulation to prevent floating-point errors
        """
        contributions = (
            self._get_contribution_value(
                self._classify_evidence(evidence_item.risk_score)
            )
            for evidence_item in evidence
        )
        return math.fsum(contributions)