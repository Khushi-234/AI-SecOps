"""
risk_engine/scoring/composite.py
=================================

Enterprise-grade composite risk scoring strategy.

This module implements the ``CompositeScorer`` concrete strategy, which
orchestrates multiple existing scoring strategies—``WeightedScorer``,
``ThresholdScorer``, and ``AdaptiveScorer``—to produce a single composite
risk score. Each sub-strategy independently computes its score via the
public ``score()`` Template Method, and CompositeScorer combines those
normalized scores using configurable strategy weights.

CompositeScorer inherits from ``BaseScorer`` and implements only the
``_score()`` algorithm. All validation, normalization, telemetry, and
exception handling are delegated to the base class Template Method.

Composite Algorithm
-------------------
For each injected scoring strategy:

    strategy_result = scorer.score(evidence, **kwargs)

Composite Score = Σ(strategy_result.score × strategy_weight)

Strategy weights are read directly from ``ScoringConfig``. The final
raw composite score is returned to ``BaseScorer.score()`` for
normalization, validation, and telemetry generation.

Strategy Composition
------------------
Scorers are injected via the constructor to support:

- Unit testing with mocks/stubs
- Runtime strategy substitution
- Future strategy additions without code modification

Complexity
----------
Time   : O(k × n) where k = number of strategies, n = len(evidence)
Memory : O(k) for intermediate strategy results (required for
         ``math.fsum``).
"""

from __future__ import annotations

import math
from typing import Any

from ..base_scorer import BaseScorer
from ...enums import ScoringStrategy
from ...models import RiskEvidence, RiskScore


__all__ = ["CompositeScorer"]


class CompositeScorer(BaseScorer):
    """
    Composite risk scoring strategy.

    Orchestrates multiple scoring strategies into a single weighted
    composite score. Delegates individual scoring to injected strategy
    instances via their public ``score()`` API and combines their
    normalized outputs using configuration-driven weights.

    Responsibilities
    --------------
    - Receive scoring strategies via dependency injection.
    - Delegate score computation to each injected strategy's public API.
    - Extract normalized scores from strategy results.
    - Combine strategy outputs using configurable weights.
    - Compute a numerically stable composite sum.

    Thread Safety
    -------------
    Completely stateless beyond the injected scorer references (which are
    themselves stateless per framework contract). Safe for concurrent use.

    Security Considerations
    -----------------------
    - Does **not** mutate input evidence or collections.
    - Does **not** execute dynamic code.
    - Operates on read-only attribute access.
    - Preserves evidence integrity.
    - Delegates to trusted, already-validated scorer instances via their
      public Template Method API.

    Future Extensibility
    --------------------
    The ``_strategies`` mapping and ``_compute_composite_score()`` helper
    are designed for extension. Additional strategies can be injected
    without modifying the composite algorithm.
    """

    # --------------------------------------------------------------------- #
    # INITIALIZATION
    # --------------------------------------------------------------------- #

    def __init__(
        self,
        weighted_scorer: BaseScorer,
        threshold_scorer: BaseScorer,
        adaptive_scorer: BaseScorer,
        **kwargs: Any,
    ) -> None:
        """
        Initialize CompositeScorer with injected scoring strategies.

        Args:
            weighted_scorer: Instance of ``WeightedScorer`` or compatible
                ``BaseScorer`` subclass.
            threshold_scorer: Instance of ``ThresholdScorer`` or compatible
                ``BaseScorer`` subclass.
            adaptive_scorer: Instance of ``AdaptiveScorer`` or compatible
                ``BaseScorer`` subclass.
            **kwargs: Forwarded to ``BaseScorer.__init__()`` for configuration
                injection.
        """
        super().__init__(**kwargs)
        self._weighted_scorer: BaseScorer = weighted_scorer
        self._threshold_scorer: BaseScorer = threshold_scorer
        self._adaptive_scorer: BaseScorer = adaptive_scorer

    # --------------------------------------------------------------------- #
    # SCORING ALGORITHM
    # --------------------------------------------------------------------- #

    def _score(self, evidence: list[RiskEvidence], **kwargs: Any) -> float:
        """
        Compute the raw composite score by combining injected strategy outputs.

        Args:
            evidence: Validated list of ``RiskEvidence`` instances.
            **kwargs: Strategy-specific parameters forwarded to sub-scorers.

        Returns:
            float: The raw composite score before normalization.
        """
        strategy_results = self._compute_strategy_results(evidence, **kwargs)
        return self._compute_composite_score(strategy_results)

    # --------------------------------------------------------------------- #
    # HELPER METHODS
    # --------------------------------------------------------------------- #

    def _compute_strategy_results(
        self,
        evidence: list[RiskEvidence],
        **kwargs: Any,
    ) -> dict[ScoringStrategy, RiskScore]:
        """
        Execute the public scoring lifecycle for each injected strategy.

        Args:
            evidence: The evidence collection to score.
            **kwargs: Forwarded to each sub-scorer's public ``score()`` method.

        Returns:
            dict[ScoringStrategy, RiskScore]: Mapping of strategy enum values
            to their fully computed ``RiskScore`` results.
        """
        return {
            ScoringStrategy.WEIGHTED: self._weighted_scorer.score(evidence, **kwargs),
            ScoringStrategy.THRESHOLD: self._threshold_scorer.score(evidence, **kwargs),
            ScoringStrategy.ADAPTIVE: self._adaptive_scorer.score(evidence, **kwargs),
        }

    def _compute_composite_score(
        self,
        strategy_results: dict[ScoringStrategy, RiskScore],
    ) -> float:
        """
        Combine individual strategy scores into a weighted composite.

        Weights are read directly from ``ScoringConfig``. Direct attribute
        access enforces fail-secure behavior: missing configuration fields
        raise ``AttributeError`` immediately rather than silently defaulting.

        Args:
            strategy_results: Mapping of strategy enum values to their
                ``RiskScore`` results.

        Returns:
            float: The numerically stable composite sum.
        """
        scoring_config = self._config.scoring

        weighted_product = (
            strategy_results[ScoringStrategy.WEIGHTED].score * scoring_config.weighted_weight
        )
        threshold_product = (
            strategy_results[ScoringStrategy.THRESHOLD].score * scoring_config.threshold_weight
        )
        adaptive_product = (
            strategy_results[ScoringStrategy.ADAPTIVE].score * scoring_config.adaptive_weight
        )

        return math.fsum((weighted_product, threshold_product, adaptive_product))