"""
risk_engine/scoring/adaptive.py
================================

Enterprise-grade adaptive risk scoring strategy.

This module implements the ``AdaptiveScorer`` concrete strategy, which
dynamically adjusts individual ``RiskEvidence`` scores using contextual
factors from ``AdaptiveConfig`` before computing a composite adaptive score.

AdaptiveScorer inherits from ``BaseScorer`` and implements only the
``_score()`` algorithm. All validation, normalization, telemetry, and
exception handling are delegated to the base class Template Method.

Algorithm
---------
For each ``RiskEvidence`` item:

    1. Start with ``base_score = evidence.risk_score``.
    2. Determine an adaptive factor using the resolution order:
       a. If detector adjustment is enabled and ``detector_name`` exists in
          ``adaptive.detector_factors``, use that factor.
       b. Else if finding-type adjustment is enabled and ``finding_type``
          exists in ``adaptive.finding_type_factors``, use that factor.
       c. Else use ``adaptive.default_factor``.
    3. ``adjusted_score = base_score × factor``.
    4. ``Composite adaptive score = math.fsum(all adjusted scores)``.

The raw composite score is returned to ``BaseScorer.score()`` for
normalization, validation, and telemetry generation.

Complexity
----------
Time   : O(n) where n = len(evidence)
Memory : O(1) auxiliary space (generator expression avoids intermediate list
         allocation).
"""

from __future__ import annotations

import math
from typing import Any

from risk_engine.base_scorer import BaseScorer
from risk_engine.models import RiskEvidence



__all__ = ["AdaptiveScorer"]


class AdaptiveScorer(BaseScorer):
    """
    Adaptive risk scoring strategy.

    Dynamically adjusts individual evidence scores using detector-specific
    and finding-type-specific factors before computing a composite sum.

    Responsibilities
    --------------
    - Implement the ``_score()`` algorithm per the Template Method Pattern.
    - Resolve adaptive factors for each evidence item.
    - Compute a numerically stable composite of adjusted scores.

    Thread Safety
    -------------
    Completely stateless. No mutable shared state. Safe for concurrent use.

    Security Considerations
    -----------------------
    - Does **not** mutate input evidence or collections.
    - Does **not** execute dynamic code.
    - Operates on read-only attribute access.
    - Preserves evidence integrity.
    - Factor bounds (enforced by ``AdaptiveConfig``) prevent extreme
      score manipulation, supporting AI governance and explainability.

    Future Extensibility
    --------------------
    The ``_get_adjustment_factor()`` resolution order is encapsulated in a
    dedicated protected method. Subclasses may override to introduce
    additional factor sources (e.g., temporal decay, threat intelligence
    feeds) without modifying the core summation logic.
    """

    # --------------------------------------------------------------------- #
    # SCORING ALGORITHM
    # --------------------------------------------------------------------- #

    def _score(self, evidence: list[RiskEvidence], **kwargs: Any) -> float:
        """
        Compute the raw adaptive composite score.

        Args:
            evidence: Validated list of ``RiskEvidence`` instances.
            **kwargs: Strategy-specific parameters (unused).

        Returns:
            float: The raw composite score before normalization.
        """
        return math.fsum(
            self._adjust_score(item)
            for item in evidence
        )

    # --------------------------------------------------------------------- #
    # HELPER METHODS
    # --------------------------------------------------------------------- #

    def _adjust_score(self, evidence: RiskEvidence) -> float:
        """
        Adjust a single evidence score by its resolved adaptive factor.

        Args:
            evidence: A single ``RiskEvidence`` instance.

        Returns:
            float: The adjusted score (base_score × factor).
        """
        factor = self._get_adjustment_factor(evidence)
        return evidence.risk_score * factor

    def _get_adjustment_factor(self, evidence: RiskEvidence) -> float:
        """
        Resolve the adaptive adjustment factor for a single evidence item.

        Resolution Order
        ----------------
        1. If detector adjustment is enabled and ``detector_name`` exists in
           ``adaptive.detector_factors``, return that factor.
        2. Else if finding-type adjustment is enabled and ``finding_type``
           exists in ``adaptive.finding_type_factors``, return that factor.
        3. Else return ``adaptive.default_factor``.

        Args:
            evidence: A single ``RiskEvidence`` instance.

        Returns:
            float: The resolved adjustment factor.
        """
        adaptive = self._config.adaptive

        # Resolution step 1: detector-specific factor
        if adaptive.enable_detector_adjustment:
            if evidence.detector_name in adaptive.detector_factors:
                return float(adaptive.detector_factors[evidence.detector_name])

        # Resolution step 2: finding-type-specific factor
        if adaptive.enable_finding_type_adjustment:
            if evidence.finding_type in adaptive.finding_type_factors:
                return float(adaptive.finding_type_factors[evidence.finding_type])

        # Resolution step 3: default fallback
        return float(adaptive.default_factor)
    