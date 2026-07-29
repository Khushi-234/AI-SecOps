"""
Risk Engine Top-Level Facade Module — Sprint 7.

Primary gateway and public API entry point for the AI-SecOps Risk Engine.

Purpose
-------
Provides `RiskEngineFacade` (and convenience module-level `RiskEngine` entry point)
which acts as the single, clean public entry point for the rest of the AI-SecOps Framework.

It hides all internal implementation details, dependency construction, and pipeline
orchestration, delegating execution directly to the underlying `RiskEngine` orchestration service.

Responsibilities
----------------
1. Instantiate and wire default dependencies via `_build_default_engine()`:
   `RiskEngineConfig`, `RiskAggregator`, `CompositeScorer` (with `WeightedScorer`,
   `ThresholdScorer`, `AdaptiveScorer`), `ConfidenceCalculator`, `PolicyMapper`,
   and `RiskEngine` orchestrator.
2. Expose a clean, intuitive public API: `evaluate()`, `evaluate_response()`, `health()`, `version()`.
3. Delegate all finding evaluation requests to the internal orchestration service.
4. Provide lightweight system health checks and framework version inspection.
5. Maintain complete thread safety and fail-secure behavior.

Architecture
------------
+-------------------------------------------------------------------------+
|                         AI-SecOps Framework                             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  risk_engine/risk_engine.py (Facade)                    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|               risk_engine/engine.py (Orchestrator Service)              |
+-------------------------------------------------------------------------+
        |                 |                      |                  |
        v                 v                      v                  v
+---------------+  +---------------+  +-------------------+  +--------------+
| RiskAggregator|  |CompositeScorer|  |ConfidenceCalculator|  | PolicyMapper |
+---------------+  +---------------+  +-------------------+  +--------------+

Complexity
----------
- **Time Complexity**: O(N log N) delegated to internal engine.
- **Memory Complexity**: O(N) linear space for evidence collections.

Thread Safety
-------------
The facade is completely stateless and thread-safe. It retains no request-specific
mutable state between calls.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Ensures complete abstraction and safe API exposure.
- Fail-Secure: Unexpected initialization or execution faults raise domain exceptions.

Future Extensibility
--------------------
Designed with open-closed principles to easily swap internal dependency wiring or
configuration providers without breaking client applications.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from risk_engine import __version__ as FRAMEWORK_VERSION
from risk_engine.aggregation import RiskAggregator
from risk_engine.config import RiskEngineConfig
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.engine import RiskEngine as InternalRiskEngine
from risk_engine.enums import ScoringStrategy
from risk_engine.exceptions import (
    RiskEngineConfigurationError,
    RiskEngineError,
)
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
)
from risk_engine.policy_mapper import PolicyMapper
from risk_engine.scoring.adaptive import AdaptiveScorer
from risk_engine.scoring.composite import CompositeScorer
from risk_engine.scoring.threshold import ThresholdScorer
from risk_engine.scoring.weighted import WeightedScorer

__all__ = ["RiskEngineFacade", "RiskEngine", "get_risk_engine"]


class RiskEngineFacade:
    """
    Public Facade service for the AI-SecOps Risk Engine.

    Encapsulates dependency wiring and exposes a clean public API for framework consumers.
    """

    def __init__(
        self,
        config: RiskEngineConfig | None = None,
        engine: InternalRiskEngine | None = None,
    ) -> None:
        """
        Initialize the RiskEngineFacade with stored config and engine assignment.

        Args:
            config: Optional RiskEngineConfig instance.
            engine: Optional pre-configured InternalRiskEngine instance.

        Raises:
            RiskEngineConfigurationError: If dependency wiring fails.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()
        self._engine: InternalRiskEngine = engine or self._build_default_engine(self._config)

    def _build_default_engine(self, config: RiskEngineConfig) -> InternalRiskEngine:
        """
        Construct and wire default component dependencies into an InternalRiskEngine.

        Args:
            config: Validated RiskEngineConfig instance.

        Returns:
            InternalRiskEngine: Fully wired orchestrator instance.

        Raises:
            RiskEngineConfigurationError: If dependency construction fails.
        """
        try:
            aggregator = RiskAggregator(config)
            weighted = WeightedScorer(config)
            threshold = ThresholdScorer(config)
            adaptive = AdaptiveScorer(config)
            scorer = CompositeScorer(
                weighted_scorer=weighted,
                threshold_scorer=threshold,
                adaptive_scorer=adaptive,
                config=config,
            )
            confidence_calculator = ConfidenceCalculator(config)
            policy_mapper = PolicyMapper(config)

            return InternalRiskEngine(
                config=config,
                aggregator=aggregator,
                scorer=scorer,
                confidence_calculator=confidence_calculator,
                policy_mapper=policy_mapper,
            )
        except RiskEngineError:
            raise
        except Exception as exc:
            raise RiskEngineConfigurationError(
                message=f"Failed to wire default RiskEngine dependencies: {exc}",
                field="facade_init",
                value=str(exc),
                cause=exc,
            ) from exc

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def evaluate(
        self,
        *sources: RiskEvidence | Sequence[RiskEvidence] | object,
        merge_strategy: str | None = None,
        confidence_strategy: str | None = None,
    ) -> RiskAssessment:
        """
        Evaluate security findings and return canonical RiskAssessment model.

        Args:
            *sources: Heterogeneous finding inputs.
            merge_strategy: Optional duplicate merge strategy override.
            confidence_strategy: Optional confidence strategy override.

        Returns:
            RiskAssessment: Immutable assessment DTO.
        """
        return self._engine.evaluate(
            *sources,
            merge_strategy=merge_strategy,
            confidence_strategy=confidence_strategy,
        )

    def evaluate_response(
        self,
        *sources: RiskEvidence | Sequence[RiskEvidence] | object,
        merge_strategy: str | None = None,
        confidence_strategy: str | None = None,
    ) -> RiskEngineResponse:
        """
        Evaluate security findings and return full RiskEngineResponse container payload.

        Args:
            *sources: Heterogeneous finding inputs.
            merge_strategy: Optional duplicate merge strategy override.
            confidence_strategy: Optional confidence strategy override.

        Returns:
            RiskEngineResponse: Gateway response container.
        """
        return self._engine.evaluate_response(
            *sources,
            merge_strategy=merge_strategy,
            confidence_strategy=confidence_strategy,
        )

    def health(self) -> dict[str, Any]:
        """
        Perform a lightweight health and status check of the Risk Engine service.

        Returns:
            dict[str, Any]: Health status metadata payload.
        """
        return {
            "status": "healthy",
            "initialized": True,
            "version": self.version(),
            "available_strategies": ScoringStrategy.values(),
            "configuration_loaded": True,
            "aggregation_strategy": self._config.aggregation.strategy,
        }

    def version(self) -> str:
        """
        Expose framework version designation.

        Returns:
            str: Risk Engine version string.
        """
        return FRAMEWORK_VERSION


# Alias RiskEngine facade for intuitive framework imports
RiskEngine = RiskEngineFacade


def get_risk_engine(config: RiskEngineConfig | None = None) -> RiskEngineFacade:
    """
    Factory function to retrieve a ready-to-use RiskEngine facade instance.

    Args:
        config: Optional custom configuration.

    Returns:
        RiskEngineFacade: Configured facade instance.
    """
    return RiskEngineFacade(config=config)
