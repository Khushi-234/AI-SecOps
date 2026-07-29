"""
risk_engine/base_scorer.py
==========================

Abstract base class for all Risk Engine scoring strategies.

This module provides the enterprise-grade foundation for risk scoring
implementations within the AI-SecOps Framework. It enforces a consistent
execution lifecycle, validation, telemetry, and error-handling contract
across all scoring strategies via the **Template Method Pattern**.

Design Patterns
---------------
- **Template Method Pattern**: ``score()`` defines the algorithm skeleton;
  ``_score()`` provides the variant step.
- **Dependency Injection**: Configuration and evidence are injected rather
  than constructed internally.

Thread Safety
-------------
``BaseScorer`` and its default helpers are stateless. Subclasses **MUST NOT**
introduce mutable shared state. All mutable data should be method-local.

Security & Governance
---------------------
- Implements **fail-secure** principles. Input validation occurs before any
  scoring computation.
- All unexpected exceptions are wrapped to prevent information leakage while
  preserving audit trails via exception chaining.
- Supports OWASP Top 10 for LLM Applications, AI Safety, Evidence
  Preservation, Auditability, Explainability, and Traceability.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, final

from risk_engine.config import RiskEngineConfig
from risk_engine.constants import (
    DEFAULT_SCORE_PRECISION,
    MAX_NORMALIZED_SCORE,
    MIN_NORMALIZED_SCORE,
    FLOAT_COMPARISON_TOLERANCE,
)
from risk_engine.enums import ScoringStrategy
from risk_engine.exceptions import (
    InvalidRiskInputError,
    RiskEngineExecutionError,
    RiskValidationError,
)
from risk_engine.models import RiskEvidence, RiskScore, RiskTelemetry
from risk_engine.utils import clamp_score, round_score, normalize_score

RISK_SCORE_MIN: float = MIN_NORMALIZED_SCORE
RISK_SCORE_MAX: float = MAX_NORMALIZED_SCORE
RISK_SCORE_PRECISION: int = DEFAULT_SCORE_PRECISION
WEIGHT_TOLERANCE: float = FLOAT_COMPARISON_TOLERANCE




__all__ = ["BaseScorer"]


class BaseScorer(ABC):
    """
    Abstract base class for all Risk Engine scoring strategies.

    Responsibilities
    --------------
    - Define the common scoring workflow (Template Method Pattern).
    - Validate inputs prior to computation.
    - Measure and record execution telemetry.
    - Normalize and validate computed scores.
    - Wrap unexpected failures in ``RiskEngineExecutionError``.
    - Preserve evidence integrity and provide audit metadata.

    Concrete subclasses must implement **only** the ``_score()`` method to
    provide their specific algorithm. All other lifecycle concerns are handled
    by this base class.

    Extensibility
    -------------
    Subclasses may override protected helper methods such as
    ``_normalize_score()``, ``_validate_score()``, or ``_build_metadata()`` to
    customize behavior without duplicating the core lifecycle.

    Thread Safety
    -------------
    This class is stateless. The injected ``config`` should be treated as
    immutable. Subclasses **MUST NOT** maintain mutable shared state across
    ``score()`` invocations.
    """

    # --------------------------------------------------------------------- #
    # INITIALIZATION
    # --------------------------------------------------------------------- #

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        """
        Initialize the scorer with optional configuration.

        Args:
            config: Risk engine configuration. If ``None``, a default
                configuration is used. Treat as immutable to maintain thread
                safety.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()

    # --------------------------------------------------------------------- #
    # PUBLIC API
    # --------------------------------------------------------------------- #

    @final
    def score(self, evidence: list[RiskEvidence], **kwargs: Any) -> RiskScore:
        """
        Execute the complete scoring lifecycle.

        Execution Lifecycle
        -------------------
        1. **Input Validation** — Validate evidence collection, item types,
           weights, and configuration.
        2. **Raw Score Computation** — Delegate to ``_score()``.
        3. **Score Normalization** — Normalize raw score to standard bounds.
        4. **Score Validation** — Ensure normalized score is within secure
           and configured limits.
        5. **Telemetry Generation** — Collect execution metrics and audit
           metadata.
        6. **RiskScore Construction** — Build and return the immutable
           ``RiskScore`` model.

        Args:
            evidence: Non-empty collection of ``RiskEvidence`` objects.
            **kwargs: Strategy-specific parameters forwarded to ``_score()``
                and helper methods.

        Returns:
            RiskScore: The computed, normalized, validated, and audited risk
            score.

        Raises:
            InvalidRiskInputError: If evidence is empty, contains invalid
                types, or fails structural validation.
            RiskValidationError: If score normalization fails, weights are
                invalid, or the final score violates bounds.
            RiskEngineExecutionError: If an unexpected runtime failure occurs
                during scoring. Preserves original exception via chaining.
        """
        start_time: float = time.perf_counter()
        raw_score: float = 0.0
        normalized_score: float = 0.0

        try:
            # Step 1: Input validation
            self._validate_inputs(evidence, **kwargs)

            # Step 2: Raw score computation (subclass-specific algorithm)
            raw_score = self._score(evidence, **kwargs)

            # Step 3: Score normalization
            normalized_score = self._normalize_score(raw_score)

            # Step 4: Normalized score validation
            self._validate_score(normalized_score)

            # Step 5: Telemetry and metadata generation
            execution_time_ms: float = self._measure_execution_time(start_time)
            metadata: dict[str, Any] = self._build_metadata(
                evidence=evidence,
                raw_score=raw_score,
                normalized_score=normalized_score,
                execution_time_ms=execution_time_ms,
                **kwargs,
            )
            telemetry: RiskTelemetry = self._generate_telemetry(metadata)

            # Step 6: Construct result model
            return self._build_risk_score(
                raw_score=raw_score,
                normalized_score=normalized_score,
                evidence=evidence,
                telemetry=telemetry,
                metadata=metadata,
                **kwargs,
            )

        except (InvalidRiskInputError, RiskValidationError):
            # Known validation errors: propagate as-is for explicit handling
            raise
        except Exception as exc:
            # Unexpected failures: wrap to prevent information leakage and
            # preserve audit chain via exception chaining (fail-secure).
            raise RiskEngineExecutionError(
                message=(
                    f"Unexpected runtime failure in {self.__class__.__name__}.score(): "
                    f"{type(exc).__name__}"
                ),
                details={"strategy": self.__class__.__name__},
                cause=exc,
            ) from exc


    # --------------------------------------------------------------------- #
    # ABSTRACT INTERFACE
    # --------------------------------------------------------------------- #

    @abstractmethod
    def _score(self, evidence: list[RiskEvidence], **kwargs: Any) -> float:
        """
        Compute the raw (un-normalized) risk score.

        This is the **sole** extension point for concrete scoring algorithms.
        Subclasses **MUST** implement this method and **MUST NOT** modify the
        input ``evidence`` collection or its elements.

        Args:
            evidence: Validated list of ``RiskEvidence`` instances.
            **kwargs: Strategy-specific parameters.

        Returns:
            float: The raw score before normalization.

        Security Note
        -------------
        Implementations should avoid external I/O or execution of dynamic
        content derived from evidence to mitigate injection risks
        (OWASP LLM01 / LLM02).
        """

    # --------------------------------------------------------------------- #
    # INPUT VALIDATION
    # --------------------------------------------------------------------- #

    def _validate_inputs(self, evidence: list[RiskEvidence], **kwargs: Any) -> None:
        """
        Validate the input evidence collection and configuration.

        Validations
        -----------
        - Evidence collection is not empty.
        - Every element is a ``RiskEvidence`` instance.
        - Evidence weights are normalized when required by configuration.
        - Configuration object is valid.

        Args:
            evidence: The evidence collection to validate.
            **kwargs: Additional parameters that may influence validation.

        Raises:
            InvalidRiskInputError: If structural evidence validation fails.
            RiskValidationError: If weight or configuration validation fails.
        """
        if not evidence:
            raise InvalidRiskInputError(
                message="Evidence collection cannot be empty.",
                field="evidence",
                value=evidence,
            )

        for index, item in enumerate(evidence):
            if not isinstance(item, RiskEvidence):
                raise InvalidRiskInputError(
                    message=(
                        f"Evidence at index {index} is not a RiskEvidence instance "
                        f"(got {type(item).__name__})."
                    ),
                    field=f"evidence[{index}]",
                    value=item,
                )

        self._validate_evidence_integrity(evidence)
        self._validate_weights(evidence)
        self._validate_configuration(self._config)

    def _validate_evidence_integrity(self, evidence: list[RiskEvidence]) -> None:
        """
        Validate evidence integrity to prevent tampering and ensure
        explainability.

        Subclasses may override to implement domain-specific integrity checks
        (e.g., cryptographic hashes, chain-of-custody validation).

        Args:
            evidence: The evidence collection to inspect.

        Security
        --------
        Supports evidence preservation and auditability requirements. Does
        **not** mutate evidence.
        """
        # Default: no-op hook for subclasses.
        pass

    def _validate_weights(self, evidence: list[RiskEvidence]) -> None:
        """
        Validate that evidence weights satisfy normalization requirements.

        If the configuration requires normalized weights, verifies that the
        sum of all evidence weights equals ``1.0`` within the configured
        tolerance.

        Args:
            evidence: The evidence collection containing weighted items.

        Raises:
            RiskValidationError: If weights are required to be normalized but
                deviate from ``1.0`` beyond the configured tolerance.
        """
        if not getattr(self._config, "require_normalized_weights", False):
            return

        weights: list[float] = []
        for idx, item in enumerate(evidence):
            weight = getattr(item, "weight", None)
            if weight is not None:
                if not isinstance(weight, (int, float)):
                    raise RiskValidationError(
                        message=f"Weight at index {idx} is not numeric.",
                        field=f"evidence[{idx}].weight",
                        value=weight,
                    )
                weights.append(float(weight))

        if not weights:
            return

        if not self._are_weights_normalized(weights):
            total: float = sum(weights)
            raise RiskValidationError(
                message=(
                    f"Evidence weights are not normalized: sum={total:.6f}, "
                    f"expected=1.0 (tolerance={self._weight_tolerance})."
                ),
                field="evidence_weights",
                value=weights,
            )

    def _are_weights_normalized(self, weights: list[float]) -> bool:
        """
        Determine whether the provided weights sum to ``1.0`` within tolerance.

        Args:
            weights: Collection of weight values.

        Returns:
            bool: ``True`` if normalized, ``False`` otherwise.
        """
        return abs(sum(weights) - 1.0) <= self._weight_tolerance

    def _validate_configuration(self, config: RiskEngineConfig) -> None:
        """
        Validate the scorer configuration object.

        Args:
            config: The configuration to validate.

        Raises:
            RiskValidationError: If the configuration is structurally invalid.
        """
        if config is None:
            return

        if hasattr(config, "validate") and callable(config.validate):
            config.validate()

    # --------------------------------------------------------------------- #
    # SCORE NORMALIZATION & VALIDATION
    # --------------------------------------------------------------------- #

    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalize a raw score to the standard secure range ``[0.0, 1.0]``.

        Default implementation clamps the value to ``[0.0, 1.0]`` and rounds
        to the configured precision. Subclasses may override for custom
        normalization (e.g., sigmoid, min-max scaling) but must preserve the
        secure bounds in ``_validate_score``.

        Args:
            raw_score: The computed raw score.

        Returns:
            float: The normalized and rounded score.

        Security
        --------
        Clamping enforces fail-secure behavior regardless of subclass
        algorithm anomalies.
        """
        score = float(raw_score)
        return normalize_score(
            score,
            min_val=RISK_SCORE_MIN,
            max_val=RISK_SCORE_MAX,
            precision=RISK_SCORE_PRECISION,
        )

    def _round_score(self, score: float, precision: int | None = None) -> float:
        """
        Round the score to the specified decimal precision.

        Args:
            score: The score to round.
            precision: Decimal places. Uses ``RISK_SCORE_PRECISION`` if
                ``None``.

        Returns:
            float: The rounded score.
        """
        places: int = precision if precision is not None else RISK_SCORE_PRECISION
        return round_score(score, precision=places)


    def _validate_score(self, normalized_score: float) -> None:
        """
        Validate that the normalized score is within acceptable bounds.

        Performs both hard secure bounds ``[0.0, 1.0]`` and configurable
        bounds validation. The secure bounds are non-negotiable to prevent
        score manipulation.

        Args:
            normalized_score: The score to validate.

        Raises:
            RiskValidationError: If the score is non-numeric or out of bounds.
        """
        if not isinstance(normalized_score, (int, float)):
            raise RiskValidationError(
                message=(
                    f"Normalized score must be numeric, got "
                    f"{type(normalized_score).__name__}."
                ),
                field="normalized_score",
                value=normalized_score,
            )

        score = float(normalized_score)

        # Hard secure bounds (fail-secure): cannot be overridden by config
        if not (RISK_SCORE_MIN <= score <= RISK_SCORE_MAX):
            raise RiskValidationError(
                message=(
                    f"Normalized score {score} violates secure bounds "
                    f"[{RISK_SCORE_MIN}, {RISK_SCORE_MAX}]."
                ),
                field="normalized_score",
                value=score,
            )

        # Configurable bounds (optional tightening)
        config_min = getattr(self._config, "min_score", RISK_SCORE_MIN)
        config_max = getattr(self._config, "max_score", RISK_SCORE_MAX)

        if not (config_min <= score <= config_max):
            raise RiskValidationError(
                message=(
                    f"Normalized score {score} is outside configured bounds "
                    f"[{config_min}, {config_max}]."
                ),
                field="normalized_score",
                value=score,
            )

    # --------------------------------------------------------------------- #
    # TELEMETRY & METADATA
    # --------------------------------------------------------------------- #

    def _measure_execution_time(self, start_time: float) -> float:
        """
        Measure elapsed execution time.

        Args:
            start_time: The high-resolution start time from
                ``time.perf_counter()``.

        Returns:
            float: Elapsed time in milliseconds.
        """
        return (time.perf_counter() - start_time) * 1000.0

    def _build_metadata(
        self,
        evidence: list[RiskEvidence],
        raw_score: float,
        normalized_score: float,
        execution_time_ms: float,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Build comprehensive metadata for telemetry, auditing, and
        explainability.

        Captures
        --------
        - Scoring strategy identity
        - Evidence summary (count, types)
        - Score values (raw and normalized)
        - Execution timing
        - Configuration reference
        - Additional strategy parameters

        Args:
            evidence: The processed evidence collection.
            raw_score: The computed raw score.
            normalized_score: The validated normalized score.
            execution_time_ms: Execution duration in milliseconds.
            **kwargs: Strategy-specific parameters for traceability.

        Returns:
            dict[str, Any]: Immutable audit metadata.

        Security
        --------
        Supports AI governance requirements: auditability, explainability,
        traceability, and evidence preservation. Does **not** capture sensitive
        evidence content to prevent data leakage in telemetry.
        """
        evidence_types: list[str] = []
        evidence_refs: list[str] = []

        for item in evidence:
            ev_type = getattr(item, "evidence_type", None)
            if ev_type is not None:
                evidence_types.append(str(ev_type))

            ev_id = getattr(item, "id", None)
            if ev_id is not None:
                evidence_refs.append(str(ev_id))

        # Deduplicate while preserving order
        unique_types = list(dict.fromkeys(evidence_types))

        return {
            "scorer_class": self.__class__.__name__,
            "scorer_module": self.__class__.__module__,
            "strategy_enum": getattr(self, "strategy", None),
            "evidence_count": len(evidence),
            "evidence_types": unique_types,
            "evidence_refs": evidence_refs,
            "raw_score": raw_score,
            "normalized_score": normalized_score,
            "execution_time_ms": execution_time_ms,
            "config_hash": getattr(self._config, "hash", None),
            "config_version": getattr(self._config, "version", None),
            "timestamp_utc": datetime.now(timezone.utc),
            "strategy_kwargs_keys": sorted(kwargs.keys()),
        }

    def _generate_telemetry(self, metadata: dict[str, Any]) -> RiskTelemetry:
        """
        Generate a structured telemetry payload from metadata.

        Collects
        --------
        - Execution time (ms)
        - Scoring strategy name
        - Processed evidence count
        - Raw score
        - Normalized score

        Args:
            metadata: The audit metadata dictionary.

        Returns:
            RiskTelemetry: Structured telemetry model.
        """
        return RiskTelemetry(
            execution_time_ms=metadata["execution_time_ms"],
            scoring_strategy=str(metadata["scorer_class"]),
            aggregation_strategy="N/A",
            confidence_strategy="N/A",
            processed_evidence_count=int(metadata["evidence_count"]),
            metadata=metadata,
        )


    # --------------------------------------------------------------------- #
    # RESULT CONSTRUCTION
    # --------------------------------------------------------------------- #

    def _build_risk_score(
        self,
        raw_score: float,
        normalized_score: float,
        evidence: list[RiskEvidence],
        telemetry: RiskTelemetry,
        metadata: dict[str, Any],
        **kwargs: Any,
    ) -> RiskScore:
        """
        Construct the final ``RiskScore`` domain model.

        Args:
            raw_score: The raw computed score.
            normalized_score: The validated normalized score.
            evidence: The original evidence collection.
            telemetry: Generated telemetry payload.
            metadata: Audit metadata dictionary.
            **kwargs: Strategy-specific parameters.

        Returns:
            RiskScore: The fully constructed, immutable risk score result.

        Security
        --------
        Preserves evidence integrity by passing references/identifiers rather
        than mutating evidence objects.
        """
        return RiskScore(
            scoring_strategy=self.__class__.__name__,
            raw_score=raw_score,
            normalized_score=normalized_score,
            weight=1.0,
            confidence=1.0,
            metadata=metadata,
        )


    # --------------------------------------------------------------------- #
    # PROPERTIES
    # --------------------------------------------------------------------- #

    @property
    def _weight_tolerance(self) -> float:
        """
        Return the tolerance for weight normalization checks.

        Reads from configuration if available; otherwise falls back to the
        framework default.

        Returns:
            float: The weight tolerance value.
        """
        return getattr(self._config, "weight_tolerance", WEIGHT_TOLERANCE)