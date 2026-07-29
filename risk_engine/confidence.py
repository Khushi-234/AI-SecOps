r"""
Risk Engine Confidence Calculation Module — Sprint 7.

Enterprise-grade confidence computation subsystem for the AI-SecOps Framework.

Purpose
-------
Provides the `ConfidenceCalculator` component responsible for computing the overall
mathematical confidence rating of an aggregated security assessment.

Confidence is distinct from risk score:
- **Risk Score**: Quantifies the estimated severity and probability of a threat.
- **Confidence**: Quantifies the mathematical certainty, agreement, and signal quality
  of the underlying evidence supporting the risk assessment.

`ConfidenceCalculator` consumes normalized `RiskEvidence` objects and returns a
normalized confidence value strictly within the range [0.0, 1.0].

Responsibilities
----------------
1. Validate structural integrity and numeric validity of input evidence [0.0, 1.0].
2. Compute detector confidence averages across upstream security findings.
3. Perform detector consensus analysis to evaluate agreement among distinct detectors.
4. Perform severity distribution consensus analysis.
5. Combine multi-factor signals into a unified, normalized confidence metric via strategy dispatch.

Confidence Workflow
-------------------
1. **Validation (`_validate_inputs`)**: Verifies non-empty evidence collections,
   correct `RiskEvidence` DTO types, and strict numeric bounds [0.0, 1.0].
2. **Signal Extraction**:
   - `_compute_confidence_average`: Mean of upstream confidence values.
   - `_compute_detector_consensus`: Standard deviation analysis across distinct detectors.
   - `_compute_severity_consensus`: Modal concentration of finding severity tiers.
   - `_compute_evidence_volume_factor`: Smooth diminishing-returns exponential curve.
3. **Strategy Dispatch**: Maps `ConfidenceStrategy` (`WEIGHTED`, `CONSENSUS`,
   `HISTORICAL`, `HYBRID`) to dedicated calculation handlers (`_calculate_weighted`,
   `_calculate_consensus`, `_calculate_historical`, `_calculate_hybrid`).
4. **Normalization (`_normalize_confidence`)**: Clamps final rating to [0.0, 1.0]
   and rounds to configured precision.

Complexity
----------
- **Time Complexity**: O(N) linear scan over N evidence items.
- **Memory Complexity**: O(K) where K is the number of distinct detectors.

Thread Safety
-------------
`ConfidenceCalculator` is completely stateless and thread-safe. It holds no
request-specific state and never mutates input evidence collections.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Ensures confidence metrics cannot be
  deflated or inflated by NaN injection or corrupted detector signals.
- Fail-Secure: Input validation raises explicit domain exceptions on invalid signals.

Future Extensibility
--------------------
Designed with open-closed principles to easily incorporate new confidence factors
(e.g., historical detector precision, temporal decay, external threat intel reputation)
without breaking existing signatures.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import Any

from risk_engine.config import RiskEngineConfig
from risk_engine.constants import (
    DEFAULT_CONFIDENCE,
    DEFAULT_DETECTOR_CONFIDENCE_WEIGHT,
    DEFAULT_HISTORICAL_CONFIDENCE_WEIGHT,
    DEFAULT_SCORE_PRECISION,
    DEFAULT_VALIDATOR_CONFIDENCE_WEIGHT,
    MAX_CONFIDENCE,
    MIN_CONFIDENCE,
)
from risk_engine.enums import ConfidenceStrategy
from risk_engine.exceptions import ConfidenceCalculationError, InvalidRiskInputError
from risk_engine.models import RiskEvidence
from risk_engine.utils import clamp_score, round_score, validate_numeric_score


__all__ = ["ConfidenceCalculator"]


#: Weight distribution for WEIGHTED strategy: (average_confidence, detector_consensus, volume_factor)
WEIGHTED_STRATEGY_WEIGHTS: tuple[float, float, float] = (
    DEFAULT_DETECTOR_CONFIDENCE_WEIGHT,
    DEFAULT_VALIDATOR_CONFIDENCE_WEIGHT,
    DEFAULT_HISTORICAL_CONFIDENCE_WEIGHT,
)

#: Weight distribution for CONSENSUS strategy: (average_confidence, detector_consensus, severity_consensus)
CONSENSUS_STRATEGY_WEIGHTS: tuple[float, float, float] = (0.30, 0.40, 0.30)

#: Weight distribution for HISTORICAL strategy: (average_confidence, detector_consensus, historical_precision)
HISTORICAL_STRATEGY_WEIGHTS: tuple[float, float, float] = (0.40, 0.30, 0.30)

#: Weight distribution for HYBRID strategy: (average_confidence, detector_consensus, severity_consensus, historical_precision, volume_factor)
HYBRID_STRATEGY_WEIGHTS: tuple[float, float, float, float, float] = (
    0.35,
    0.25,
    0.20,
    0.10,
    0.10,
)


class ConfidenceCalculator:
    """
    Stateless, enterprise-grade Confidence Calculator.

    Computes mathematical confidence metrics for aggregated security assessments.
    """

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        """
        Initialize ConfidenceCalculator with optional configuration.

        Args:
            config: Risk Engine configuration instance. Uses default if None.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()
        self._strategy_dispatch: dict[
            ConfidenceStrategy,
            Callable[[Sequence[RiskEvidence], float], float],
        ] = {
            ConfidenceStrategy.WEIGHTED: self._calculate_weighted,
            ConfidenceStrategy.CONSENSUS: self._calculate_consensus,
            ConfidenceStrategy.HISTORICAL: self._calculate_historical,
            ConfidenceStrategy.HYBRID: self._calculate_hybrid,
        }

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def calculate(
        self,
        evidence: Sequence[RiskEvidence],
        strategy: ConfidenceStrategy | str | None = None,
        historical_precision: float = 0.85,
        **kwargs: Any,
    ) -> float:
        """
        Calculate overall normalized confidence level for a collection of RiskEvidence.

        Args:
            evidence: Non-empty collection of RiskEvidence objects.
            strategy: Optional confidence strategy override (WEIGHTED, CONSENSUS, HISTORICAL, HYBRID).
            historical_precision: Explicit historical accuracy signal in range [0.0, 1.0].
            **kwargs: Backward-compatible keyword arguments.

        Returns:
            float: Normalized confidence rating clamped to [0.0, 1.0].

        Raises:
            InvalidRiskInputError: If evidence collection is empty or contains invalid items.
            ConfidenceCalculationError: If an error occurs during confidence calculation.
        """
        self._validate_inputs(evidence)

        try:
            strategy_enum = self._resolve_strategy(strategy)
            hist_prec = float(kwargs.get("historical_precision", historical_precision))

            handler = self._strategy_dispatch.get(
                strategy_enum, self._calculate_weighted
            )
            raw_confidence = handler(evidence, hist_prec)

            return self._normalize_confidence(raw_confidence)

        except (InvalidRiskInputError, ConfidenceCalculationError):
            raise
        except Exception as exc:
            raise ConfidenceCalculationError(
                message=f"Failed to calculate confidence: {exc}",
                details={"evidence_count": len(evidence)},
                cause=exc,
            ) from exc

    # =========================================================================
    # DEDICATED STRATEGY HANDLERS
    # =========================================================================

    def _calculate_weighted(
        self,
        evidence: Sequence[RiskEvidence],
        historical_precision: float,
    ) -> float:
        """Calculate confidence using WEIGHTED strategy."""
        avg_confidence = self._compute_confidence_average(evidence)
        detector_consensus = self._compute_detector_consensus(evidence)
        volume_factor = self._compute_evidence_volume_factor(evidence)

        w_avg, w_consensus, w_volume = WEIGHTED_STRATEGY_WEIGHTS
        return math.fsum(
            [
                avg_confidence * w_avg,
                detector_consensus * w_consensus,
                volume_factor * w_volume,
            ]
        )

    def _calculate_consensus(
        self,
        evidence: Sequence[RiskEvidence],
        historical_precision: float,
    ) -> float:
        """Calculate confidence using CONSENSUS strategy."""
        avg_confidence = self._compute_confidence_average(evidence)
        detector_consensus = self._compute_detector_consensus(evidence)
        severity_consensus = self._compute_severity_consensus(evidence)

        w_avg, w_det, w_sev = CONSENSUS_STRATEGY_WEIGHTS
        return math.fsum(
            [
                avg_confidence * w_avg,
                detector_consensus * w_det,
                severity_consensus * w_sev,
            ]
        )

    def _calculate_historical(
        self,
        evidence: Sequence[RiskEvidence],
        historical_precision: float,
    ) -> float:
        """Calculate confidence using HISTORICAL strategy."""
        avg_confidence = self._compute_confidence_average(evidence)
        detector_consensus = self._compute_detector_consensus(evidence)

        w_avg, w_det, w_hist = HISTORICAL_STRATEGY_WEIGHTS
        return math.fsum(
            [
                avg_confidence * w_avg,
                detector_consensus * w_det,
                historical_precision * w_hist,
            ]
        )

    def _calculate_hybrid(
        self,
        evidence: Sequence[RiskEvidence],
        historical_precision: float,
    ) -> float:
        """Calculate confidence using HYBRID strategy."""
        avg_confidence = self._compute_confidence_average(evidence)
        detector_consensus = self._compute_detector_consensus(evidence)
        severity_consensus = self._compute_severity_consensus(evidence)
        volume_factor = self._compute_evidence_volume_factor(evidence)

        w_avg, w_det, w_sev, w_hist, w_vol = HYBRID_STRATEGY_WEIGHTS
        return math.fsum(
            [
                avg_confidence * w_avg,
                detector_consensus * w_det,
                severity_consensus * w_sev,
                historical_precision * w_hist,
                volume_factor * w_vol,
            ]
        )

    # =========================================================================
    # PROTECTED HELPER METHODS
    # =========================================================================

    def _validate_inputs(self, evidence: Sequence[RiskEvidence]) -> None:
        """
        Validate input evidence sequence for structural and numeric integrity.

        Args:
            evidence: Collection of RiskEvidence objects.

        Raises:
            InvalidRiskInputError: If evidence is empty, invalid type, or out of bounds [0.0, 1.0].
        """
        if not evidence:
            raise InvalidRiskInputError(
                message="Evidence collection cannot be empty for confidence calculation.",
                field="evidence",
                value=evidence,
            )

        for idx, item in enumerate(evidence):
            if not isinstance(item, RiskEvidence):
                raise InvalidRiskInputError(
                    message=f"Item at index {idx} is not a RiskEvidence instance (got {type(item).__name__}).",
                    details={"field": f"evidence[{idx}]", "value": item},
                )

            validate_numeric_score(item.confidence, field_name=f"evidence[{idx}].confidence")
            validate_numeric_score(item.risk_score, field_name=f"evidence[{idx}].risk_score")


    def _compute_confidence_average(self, evidence: Sequence[RiskEvidence]) -> float:
        """
        Compute the mean upstream confidence rating across evidence items.

        Args:
            evidence: Validated sequence of RiskEvidence objects.

        Returns:
            float: Average confidence value.
        """
        if not evidence:
            return self._config.confidence.default_confidence

        total = math.fsum(item.confidence for item in evidence)
        return total / float(len(evidence))

    def _compute_detector_consensus(self, evidence: Sequence[RiskEvidence]) -> float:
        """
        Evaluate risk score agreement among distinct upstream detectors to reduce detector bias.

        Groups findings by detector_name to compute mean score per detector before
        calculating inter-detector standard deviation.

        Args:
            evidence: Validated sequence of RiskEvidence objects.

        Returns:
            float: Consensus signal in range [0.0, 1.0].
        """
        detector_scores: dict[str, list[float]] = {}
        for item in evidence:
            detector_scores.setdefault(item.detector_name, []).append(item.risk_score)

        detector_means = [
            math.fsum(scores) / float(len(scores))
            for scores in detector_scores.values()
        ]

        n_detectors = len(detector_means)
        if n_detectors <= 1:
            return 1.0

        mean_score = math.fsum(detector_means) / float(n_detectors)
        variance = (
            math.fsum((score - mean_score) ** 2 for score in detector_means)
            / float(n_detectors)
        )
        std_dev = math.sqrt(variance)

        # Standard deviation for bounded [0, 1] variables ranges [0.0, 0.5]
        consensus = 1.0 - (2.0 * std_dev)
        return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, consensus))

    def _compute_severity_consensus(self, evidence: Sequence[RiskEvidence]) -> float:
        """
        Evaluate distribution consensus across finding severities.

        High concentration in a single severity tier indicates high consensus.

        Args:
            evidence: Validated sequence of RiskEvidence objects.

        Returns:
            float: Severity consensus signal in range [0.0, 1.0].
        """
        n = len(evidence)
        if n <= 1:
            return 1.0

        counts: dict[str, int] = {}
        for item in evidence:
            sev = item.severity.upper()
            counts[sev] = counts.get(sev, 0) + 1

        max_count = max(counts.values())
        return float(max_count) / float(n)

    def _compute_evidence_volume_factor(self, evidence: Sequence[RiskEvidence]) -> float:
        """
        Compute smooth diminishing-returns scaling factor based on evidence volume.

        Uses exponential saturation curve bounded strictly within [0.5, 1.0].

        Args:
            evidence: Validated sequence of RiskEvidence objects.

        Returns:
            float: Volume factor in range [0.5, 1.0].
        """
        n = len(evidence)
        if n <= 0:
            return 0.5
        # Smooth diminishing returns: N=1 -> 0.5, N=2 -> 0.75, N=3 -> 0.875, N=4 -> 0.9375, N->inf -> 1.0
        factor = 1.0 - (0.5 * (0.5 ** (n - 1)))
        return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, factor))

    def _normalize_confidence(self, raw_confidence: float) -> float:
        """
        Normalize and clamp raw confidence to configured secure bounds.

        Args:
            raw_confidence: Calculated raw confidence value.

        Returns:
            float: Clamped, rounded confidence rating in [0.0, 1.0].

        Raises:
            ConfidenceCalculationError: If raw confidence is NaN or Infinite.
        """
        min_c = self._config.confidence.min_confidence
        max_c = self._config.confidence.max_confidence

        clamped = clamp_score(raw_confidence, min_val=min_c, max_val=max_c)
        return round_score(clamped, precision=DEFAULT_SCORE_PRECISION)


    def _resolve_strategy(
        self,
        strategy: ConfidenceStrategy | str | None,
    ) -> ConfidenceStrategy:
        """Resolve ConfidenceStrategy enum value from optional input parameter or configuration."""
        if strategy is not None:
            if isinstance(strategy, ConfidenceStrategy):
                return strategy
            if isinstance(strategy, str):
                return ConfidenceStrategy.from_string(strategy)

        # Configuration-driven default lookup
        config_strategy = getattr(self._config.confidence, "strategy", None)
        if config_strategy is not None:
            if isinstance(config_strategy, ConfidenceStrategy):
                return config_strategy
            if isinstance(config_strategy, str) and ConfidenceStrategy.has_value(config_strategy):
                return ConfidenceStrategy.from_string(config_strategy)

        return ConfidenceStrategy.WEIGHTED
