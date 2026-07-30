"""
Risk Engine Aggregation Module — Sprint 7.

Centralized evidence collection, normalization, deduplication, and deterministic
ordering subsystem for the AI-SecOps Framework.

Purpose
-------
Provides the `RiskAggregator` component responsible for consolidating security
findings emitted by upstream modules (such as Prompt Firewall and Input Validator)
into a unified, normalized, deduplicated, and deterministically ordered collection
of `RiskEvidence` domain models.

`RiskAggregator` prepares clean, normalized evidence for downstream risk scoring
calculators (`BaseScorer`, `WeightedScorer`, `ThresholdScorer`, `AdaptiveScorer`,
`CompositeScorer`).

Responsibilities
----------------
1. Collect evidence from multiple upstream security modules.
2. Normalize heterogenous upstream finding structures (`ValidationResult`,
   `DetectionResult`, `RiskEvidence`, `FirewallResponse`, `InputValidationResponse`, dicts)
   into canonical `RiskEvidence` objects via dedicated normalization handlers.
3. Deduplicate identical or redundant security findings.
4. Merge related findings while preserving complete audit metadata.
5. Maintain strict source attribution and evidence provenance.
6. Enforce 100% deterministic output ordering across repeated executions.

Aggregation Workflow
--------------------
1. **Input Collection (`_collect_evidence`)**: Recursively unpacks multi-source
   inputs and generic iterables into a flat sequence of raw finding items.
2. **Normalization (`_normalize`)**: Dispatches each raw finding to a specialized
   normalization helper (`_normalize_risk_evidence`, `_normalize_validation_result`,
   `_normalize_detection_result`, `_normalize_duck_validation_result`,
   `_normalize_duck_detection_result`, `_normalize_dict`).
3. **Deduplication & Merging (`_merge_duplicates`)**: Groups findings by compound
   fingerprint and applies configurable merge strategies (`HIGHEST_SCORE`,
   `FIRST_MATCH`, `MERGE_ALL`, `DEDUPLICATE`) without metadata loss.
4. **D
eterministic Sorting (`_sort_evidence`)**: Sorts aggregated evidence by
   risk score (descending), confidence (descending), severity rank (descending),
   and lexicographical identity (source, detector, finding_type, evidence_id).

Deduplication Strategy
----------------------
Duplicate findings sharing the same source module, detector name, finding type,
and target content fingerprint are merged according to the configured `MergeStrategy`.
- `HIGHEST_SCORE`: Retains the maximum risk score and confidence rating while
  combining metadata, preventing score deflation from duplicate signals.
- `FIRST_MATCH`: Retains the first observed finding while accumulating metadata.
- `MERGE_ALL`: Retains all findings distinctly while attaching group telemetry.
- `DEDUPLICATE`: Eliminates exact duplicates, keeping the highest severity entry.

Complexity
----------
- **Time Complexity**: O(N log N) dominated by deterministic sorting, where N is
  the number of normalized evidence items. Collection and deduplication run in O(N).
- **Memory Complexity**: O(N) linear auxiliary space with respect to evidence count.

Thread Safety
-------------
`RiskAggregator` is completely stateless and thread-safe. It does not maintain
mutable shared state across invocations. Inputs are never mutated in-place;
all operations return newly created collections.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Preserves complete evidence provenance,
  matched text, and detector metadata for AI security governance and auditability.
- Fail-Secure: Input validation and direct configuration checks prevent unhandled
  exceptions from corrupting evidence.

Future Extensibility
--------------------
Designed with open-closed principles to seamlessly ingest evidence from future
pipeline stages (e.g., Output Guard, Policy Engine, RAG Scanner, Threat Intelligence)
without modification to core aggregation logic or direct package coupling.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from risk_engine.config import RiskEngineConfig
from risk_engine.constants import SEVERITY_RANKING, SEVERITY_SCORE_MAP
from risk_engine.enums import EvidenceSource, FindingSeverity, MergeStrategy
from risk_engine.exceptions import InvalidRiskInputError, RiskAggregationError
from risk_engine.models import RiskEvidence
from risk_engine.utils import round_score, to_immutable_tuple


__all__ = ["RiskAggregator"]


class RiskAggregator:
    """
    Stateless, enterprise-grade Risk Aggregator.

    Consolidates security findings from Prompt Firewall, Input Validator, and future
    detection modules into a normalized, deduplicated, and deterministically ordered
    collection of `RiskEvidence` objects.
    """

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        """
        Initialize the RiskAggregator with optional configuration.

        Args:
            config: Risk Engine configuration instance. Uses default if None.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def aggregate(
        self,
        *sources: Any,
        merge_strategy: MergeStrategy | str | None = None,
    ) -> list[RiskEvidence]:

    
        """
        Aggregate multi-source security findings into a unified RiskEvidence collection.

        Args:
            *sources: Heterogeneous finding inputs (RiskEvidence, ValidationResult,
                DetectionResult, InputValidationResponse, FirewallResponse, iterables, dicts).
            merge_strategy: Optional override for duplicate merge strategy. If None,
                uses framework default (`MergeStrategy.HIGHEST_SCORE`).

        Returns:
            list[RiskEvidence]: Normalized, deduplicated, and deterministically ordered
            collection of immutable `RiskEvidence` items.

        Raises:
            InvalidRiskInputError: If sources are empty or unparseable.
            RiskAggregationError: If an error occurs during aggregation processing.
        """
        if not sources:
            raise InvalidRiskInputError(
                message="Aggregation input sources cannot be empty.",
                field="sources",
                value=sources,
            )

        try:
            # Step 1: Collect raw evidence items from all input sources
            raw_items = self._collect_evidence(*sources)

            if not raw_items:
                raise InvalidRiskInputError(
                    message="No valid evidence items extracted from input sources.",
                    field="sources",
                    value=sources,
                )

            # Step 2: Normalize raw items into unified RiskEvidence DTOs via dispatcher
            normalized = [self._normalize(item) for item in raw_items]

            # Step 3: Deduplicate and merge related findings
            strategy_enum = self._resolve_merge_strategy(merge_strategy)
            merged = self._merge_duplicates(normalized, strategy=strategy_enum)

            # Step 4: Sort evidence deterministically
            sorted_evidence = self._sort_evidence(merged)

            return sorted_evidence

        except (InvalidRiskInputError, RiskAggregationError):
            raise
        except Exception as exc:
            raise RiskAggregationError(
                message=f"Failed to aggregate evidence: {exc}",
                details={"sources_count": len(sources)},
                cause=exc,
            ) from exc

    # =========================================================================
    # PROTECTED LIFE-CYCLE HELPER METHODS
    # =========================================================================

    def _collect_evidence(self, *sources: Any) -> list[Any]:
        """
        Recursively extract individual finding objects from input arguments and generic iterables.

        Excludes `str` and `bytes` from iterable expansion.

        Args:
            *sources: Heterogeneous finding inputs or iterables.

        Returns:
            list[Any]: Flattened list of individual raw finding objects.
        """
        collected: list[Any] = []

        for source in sources:
            if source is None:
                continue

            # Unpack response containers possessing a 'results' or 'evidence' iterable attribute
            if hasattr(source, "results") and isinstance(getattr(source, "results"), Iterable) and not isinstance(getattr(source, "results"), (str, bytes)):
                collected.extend(self._collect_evidence(*getattr(source, "results")))

            elif hasattr(source, "evidence") and isinstance(getattr(source, "evidence"), Iterable) and not isinstance(getattr(source, "evidence"), (str, bytes)):
                collected.extend(self._collect_evidence(*getattr(source, "evidence")))

            # Unpack dictionary structures containing result lists or individual findings
            elif isinstance(source, dict):
                if "results" in source and isinstance(source["results"], Iterable) and not isinstance(source["results"], (str, bytes)):
                    collected.extend(self._collect_evidence(*source["results"]))
                elif "evidence" in source and isinstance(source["evidence"], Iterable) and not isinstance(source["evidence"], (str, bytes)):
                    collected.extend(self._collect_evidence(*source["evidence"]))
                else:
                    collected.append(source)

            # Unpack generic iterables (lists, tuples, sets, generators) excluding str and bytes
            elif isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
                for item in source:
                    collected.extend(self._collect_evidence(item))

            # Individual domain model objects
            else:
                collected.append(source)

        return collected

    def _normalize(self, item: Any) -> RiskEvidence:
        """
        Dispatch a raw finding item to its dedicated normalization helper.

        Single Responsibility Dispatcher.

        Args:
            item: Raw finding object (RiskEvidence, ValidationResult, DetectionResult, or dict).

        Returns:
            RiskEvidence: Canonical immutable evidence DTO.

        Raises:
            RiskAggregationError: If item cannot be mapped to RiskEvidence.
        """
        if isinstance(item, RiskEvidence):
            return self._normalize_risk_evidence(item)

        if type(item).__name__ == "ValidationResult":
            return self._normalize_validation_result(item)

        if type(item).__name__ == "DetectionResult":
            return self._normalize_detection_result(item)

        if hasattr(item, "validator_name") and hasattr(item, "is_valid"):
            return self._normalize_duck_validation_result(item)

        if hasattr(item, "detector_name") and hasattr(item, "severity"):
            return self._normalize_duck_detection_result(item)

        if isinstance(item, dict):
            return self._normalize_dict(item)

        raise RiskAggregationError(
            message=f"Unsupported evidence object type for normalization: {type(item).__name__}",
            details={"item_type": type(item).__name__},
        )

    def _merge_duplicates(
        self,
        evidence: list[RiskEvidence],
        strategy: MergeStrategy,
    ) -> list[RiskEvidence]:
        """
        Deduplicate and merge related RiskEvidence items according to strategy.

        Args:
            evidence: List of normalized RiskEvidence items.
            strategy: MergeStrategy enum value.

        Returns:
            list[RiskEvidence]: Merged RiskEvidence collection.
        """
        if strategy == MergeStrategy.MERGE_ALL:
            return list(evidence)

        # Group evidence items by duplicate fingerprint key
        grouped: dict[tuple[str, str, str, str], list[RiskEvidence]] = {}
        for item in evidence:
            key = self._generate_dedup_key(item)
            grouped.setdefault(key, []).append(item)

        merged_results: list[RiskEvidence] = []
        for key, group in grouped.items():
            if len(group) == 1:
                merged_results.append(group[0])
            else:
                merged_item = self._combine_duplicate_group(group, strategy)
                merged_results.append(merged_item)

        return merged_results

    def _sort_evidence(self, evidence: list[RiskEvidence]) -> list[RiskEvidence]:
        """
        Sort evidence deterministically.

        Sort Hierarchy:
            1. risk_score descending (highest risk first)
            2. confidence descending
            3. severity rank descending (CRITICAL > HIGH > MEDIUM > LOW > INFO)
            4. source_module ascending (lexicographical)
            5. detector_name ascending (lexicographical)
            6. finding_type ascending (lexicographical)
            7. evidence_id ascending (lexicographical)

        Args:
            evidence: Collection of RiskEvidence items.

        Returns:
            list[RiskEvidence]: Deterministically sorted RiskEvidence items.
        """

        def sort_key(item: RiskEvidence) -> tuple[float, float, int, str, str, str, str]:
            sev_rank = SEVERITY_RANKING.get(str(item.severity).upper(), 0)
            return (
                -item.risk_score,
                -item.confidence,
                -sev_rank,
                item.source_module.upper(),
                item.detector_name.upper(),
                item.finding_type.upper(),
                item.evidence_id,
            )

        return sorted(evidence, key=sort_key)

    # =========================================================================
    # DEDICATED NORMALIZATION HELPER METHODS
    # =========================================================================

    def _normalize_risk_evidence(self, item: RiskEvidence) -> RiskEvidence:
        """Normalize a pre-existing RiskEvidence object (pass-through)."""
        return item

    def _normalize_validation_result(self, item: Any) -> RiskEvidence:
        """Normalize InputValidator ValidationResult into RiskEvidence."""
        is_valid = bool(item.is_valid)
        meta = dict(item.metadata) if item.metadata else {}

        finding_type = meta.get(
            "finding_type",
            "COMPLIANT_INPUT" if is_valid else "STRUCTURAL_ANOMALY",
        )
        severity = meta.get(
            "severity",
            FindingSeverity.INFO.value if is_valid else FindingSeverity.MEDIUM.value,
        )
        confidence = float(meta.get("confidence", 1.0))
        risk_score = float(meta.get("risk_score", 0.0 if is_valid else 0.70))
        description = (
            item.error_message
            or f"Validator '{item.validator_name}' {'passed' if is_valid else 'failed'}."
        )

        meta.update(
            {
                "is_valid": is_valid,
                "execution_time_ms": getattr(item, "execution_time_ms", 0.0),
            }
        )

        ts = getattr(item, "timestamp", datetime.now(timezone.utc))
        if ts is None or not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        matched_text = str(meta.get("matched_text", ""))
        ev_id = meta.get("evidence_id") or self._generate_deterministic_id(
            EvidenceSource.INPUT_VALIDATOR.value, item.validator_name, finding_type, matched_text
        )

        return RiskEvidence(
            evidence_id=ev_id,
            source_module=EvidenceSource.INPUT_VALIDATOR.value,
            detector_name=item.validator_name,
            finding_type=finding_type,
            severity=str(severity).upper(),
            confidence=confidence,
            risk_score=risk_score,
            description=description,
            metadata=meta,
            timestamp=ts,
        )

    def _normalize_detection_result(self, item: Any) -> RiskEvidence:
        """Normalize PromptFirewall DetectionResult into RiskEvidence."""
        meta = dict(item.metadata) if item.metadata else {}

        threat_val = (
            item.threat_type.value if hasattr(item.threat_type, "value") else str(item.threat_type)
        )
        sev_val = (
            item.severity.value if hasattr(item.severity, "value") else str(item.severity)
        ).upper()

        risk_score = float(
            meta.get("risk_score", SEVERITY_SCORE_MAP.get(sev_val, 0.50))
        )
        description = (
            getattr(item, "evidence", "")
            or getattr(item, "matched_text", "")
            or f"Security finding detected by '{item.detector_name}'."
        )

        matched_text = str(getattr(item, "matched_text", ""))
        meta.update(
            {
                "request_id": getattr(item, "request_id", ""),
                "matched_text": matched_text,
                "execution_time_ms": getattr(item, "execution_time_ms", 0.0),
                "status": (
                    item.status.value if hasattr(item.status, "value") else str(item.status)
                ),
            }
        )

        ts = getattr(item, "timestamp", datetime.now(timezone.utc))
        if ts is None or not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        ev_id = meta.get("evidence_id") or self._generate_deterministic_id(
            EvidenceSource.PROMPT_FIREWALL.value, item.detector_name, threat_val, matched_text
        )

        return RiskEvidence(
            evidence_id=ev_id,
            source_module=EvidenceSource.PROMPT_FIREWALL.value,
            detector_name=item.detector_name,
            finding_type=str(threat_val),
            severity=sev_val,
            confidence=float(item.confidence),
            risk_score=risk_score,
            description=description,
            metadata=meta,
            timestamp=ts,
        )

    def _normalize_duck_validation_result(self, item: Any) -> RiskEvidence:
        """Duck-typing normalization for ValidationResult-like objects."""
        is_valid = bool(getattr(item, "is_valid", False))
        meta = dict(getattr(item, "metadata", {}) or {})
        validator_name = str(getattr(item, "validator_name", "UnknownValidator"))

        finding_type = str(
            meta.get("finding_type", "COMPLIANT_INPUT" if is_valid else "STRUCTURAL_ANOMALY")
        )
        severity = str(
            meta.get("severity", FindingSeverity.INFO.value if is_valid else FindingSeverity.MEDIUM.value)
        ).upper()

        risk_score = float(meta.get("risk_score", 0.0 if is_valid else 0.70))
        confidence = float(meta.get("confidence", 1.0))
        error_msg = getattr(item, "error_message", None)
        description = error_msg or f"Validator '{validator_name}' {'passed' if is_valid else 'failed'}."

        ts = getattr(item, "timestamp", datetime.now(timezone.utc))
        if ts is None or not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        matched_text = str(meta.get("matched_text", ""))
        ev_id = meta.get("evidence_id") or self._generate_deterministic_id(
            EvidenceSource.INPUT_VALIDATOR.value, validator_name, finding_type, matched_text
        )

        return RiskEvidence(
            evidence_id=ev_id,
            source_module=EvidenceSource.INPUT_VALIDATOR.value,
            detector_name=validator_name,
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            description=description,
            metadata=meta,
            timestamp=ts,
        )

    def _normalize_duck_detection_result(self, item: Any) -> RiskEvidence:
        """Duck-typing normalization for DetectionResult-like objects."""
        meta = dict(getattr(item, "metadata", {}) or {})
        detector_name = str(getattr(item, "detector_name", "UnknownDetector"))
        threat_attr = getattr(item, "threat_type", "SECURITY_FINDING")
        threat_val = threat_attr.value if hasattr(threat_attr, "value") else str(threat_attr)

        sev_attr = getattr(item, "severity", FindingSeverity.MEDIUM.value)
        sev_val = (sev_attr.value if hasattr(sev_attr, "value") else str(sev_attr)).upper()

        confidence = float(getattr(item, "confidence", 1.0))
        risk_score = float(meta.get("risk_score", SEVERITY_SCORE_MAP.get(sev_val, 0.50)))
        evidence_text = getattr(item, "evidence", "") or getattr(item, "matched_text", "")
        description = evidence_text or f"Finding from detector '{detector_name}'."

        ts = getattr(item, "timestamp", datetime.now(timezone.utc))
        if ts is None or not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        matched_text = str(getattr(item, "matched_text", meta.get("matched_text", "")))
        ev_id = meta.get("evidence_id") or self._generate_deterministic_id(
            EvidenceSource.PROMPT_FIREWALL.value, detector_name, threat_val, matched_text
        )

        return RiskEvidence(
            evidence_id=ev_id,
            source_module=EvidenceSource.PROMPT_FIREWALL.value,
            detector_name=detector_name,
            finding_type=threat_val,
            severity=sev_val,
            confidence=confidence,
            risk_score=risk_score,
            description=description,
            metadata=meta,
            timestamp=ts,
        )

    def _normalize_dict(self, item: dict[str, Any]) -> RiskEvidence:
        """Normalize a dictionary finding structure into RiskEvidence."""
        source_module = str(
            item.get("source_module", EvidenceSource.INPUT_VALIDATOR.value)
        )
        detector_name = str(item.get("detector_name", item.get("validator_name", "DictDetector")))
        finding_type = str(item.get("finding_type", item.get("threat_type", "GENERIC_FINDING")))
        severity = str(item.get("severity", FindingSeverity.MEDIUM.value)).upper()

        confidence = float(item.get("confidence", 1.0))
        risk_score = float(
            item.get("risk_score", SEVERITY_SCORE_MAP.get(severity, 0.50))
        )
        description = str(
            item.get("description", item.get("error_message", item.get("evidence", "Dictionary finding.")))
        )

        meta = dict(item.get("metadata", {}))

        ts_raw = item.get("timestamp")
        if isinstance(ts_raw, datetime):
            ts = ts_raw if ts_raw.tzinfo is not None else ts_raw.replace(tzinfo=timezone.utc)
        elif isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        matched_text = str(meta.get("matched_text", item.get("matched_text", "")))
        ev_id = str(item.get("evidence_id", item.get("id", ""))) or self._generate_deterministic_id(
            source_module, detector_name, finding_type, matched_text
        )

        return RiskEvidence(
            evidence_id=ev_id,
            source_module=source_module,
            detector_name=detector_name,
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            description=description,
            metadata=meta,
            timestamp=ts,
        )

    # =========================================================================
    # PRIVATE DEDUPLICATION HELPERS
    # =========================================================================

    def _generate_dedup_key(self, item: RiskEvidence) -> tuple[str, str, str, str]:
        """
        Generate a unique duplicate fingerprint key for a RiskEvidence item.

        Fingerprint: (source_module, detector_name, finding_type, target_matched_text)
        """
        matched_text = str(item.metadata.get("matched_text", "")).strip()
        return (
            item.source_module.upper(),
            item.detector_name.upper(),
            item.finding_type.upper(),
            matched_text,
        )

    def _combine_duplicate_group(
        self,
        group: list[RiskEvidence],
        strategy: MergeStrategy,
    ) -> RiskEvidence:
        """
        Merge a group of duplicate RiskEvidence items into a single RiskEvidence item.

        Args:
            group: Non-empty list of duplicate RiskEvidence items.
            strategy: MergeStrategy enum value.

        Returns:
            RiskEvidence: Merged RiskEvidence item.
        """
        if strategy == MergeStrategy.FIRST_MATCH:
            primary = group[0]
        else:
            # HIGHEST_SCORE / DEDUPLICATE default: select item with highest risk score
            primary = max(group, key=lambda x: (x.risk_score, x.confidence))

        # Merge metadata dictionaries across all duplicates in group
        combined_meta = dict(primary.metadata)
        combined_meta["merged_count"] = len(group)
        combined_meta["duplicate_evidence_ids"] = [item.evidence_id for item in group]
        combined_meta["raw_scores"] = [item.risk_score for item in group]
        combined_meta["confidences"] = [item.confidence for item in group]

        max_confidence = max(item.confidence for item in group)
        max_score = max(item.risk_score for item in group) if strategy != MergeStrategy.FIRST_MATCH else primary.risk_score

        return RiskEvidence(
            evidence_id=primary.evidence_id,
            source_module=primary.source_module,
            detector_name=primary.detector_name,
            finding_type=primary.finding_type,
            severity=primary.severity,
            confidence=max_confidence,
            risk_score=max_score,
            description=primary.description,
            metadata=combined_meta,
            timestamp=primary.timestamp,
        )

    def _resolve_merge_strategy(
        self,
        override_strategy: MergeStrategy | str | None,
    ) -> MergeStrategy:
        """
        Resolve MergeStrategy enum value from optional override or configuration.

        Fail-secure direct attribute access.
        """
        if override_strategy is not None:
            if isinstance(override_strategy, MergeStrategy):
                return override_strategy
            if isinstance(override_strategy, str):
                return MergeStrategy.from_string(override_strategy)

        # Fail-secure direct configuration access
        config_strategy = self._config.aggregation.strategy
        if isinstance(config_strategy, MergeStrategy):
            return config_strategy
        if isinstance(config_strategy, str):
            if MergeStrategy.has_value(config_strategy):
                return MergeStrategy.from_string(config_strategy)

        return MergeStrategy.HIGHEST_SCORE

    def _generate_deterministic_id(
        self,
        source: str,
        detector: str,
        finding_type: str,
        matched_text: str = "",
    ) -> str:
        """
        Generate a stable, deterministic UUIDv5 identifier based on finding identity fields.

        The same logical finding generates the exact same identifier regardless of execution time.
        """
        namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # DNS namespace
        normalized_text = matched_text.strip()
        name = f"{source.upper()}:{detector.upper()}:{finding_type.upper()}:{normalized_text}"
        return str(uuid.uuid5(namespace, name))
