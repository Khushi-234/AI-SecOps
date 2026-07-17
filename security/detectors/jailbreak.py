"""
Jailbreak Detector Module
Assigned to: Khushi

Detects LLM jailbreak attempts including Persona Adoption (e.g. DAN, Developer Mode),
Evil Prompts, Refusal Suppression, hypothetical scenario bypasses, and prefix injections.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from security.base_detector import BaseDetector, DetectorConfig
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.exceptions import ConfigurationError, DetectorExecutionError, RuleLoadingError
from security.models import DetectionResult


class JailbreakDetector(BaseDetector):
    """
    Scans prompts for known jailbreak attacks, structural bypasses, and roleplay tricks.

    Execution Pipeline:
    -------------------
    1. Validation: Verifies if detector is active in configs. If disabled, skips analysis.
    2. Input Extraction: Resolves tracking metrics and context request_id parameters.
    3. Regex matching: Iterates over precompiled pattern match rules.
    4. Keyword matching: Scans prompt word-tokens against rules-defined keyword lists.
    5. Phrase matching: Checks substring containment against rules-defined trigger phrases.
    6. Aggregation: Collects all matched instances across rules.
    7. Priority selection: Selects the highest priority rule (lowest number) using min().
    8. DTO compilation: Packages findings into a standard DetectionResult object.
    """

    @property
    def detector_name(self) -> str:
        return "JailbreakDetector"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        """
        Initializes the detector, locating and loading the rule configuration.

        Args:
            config: Configurations defining custom thresholds or file overrides.
        """
        super().__init__(config)

        # Locate rules database file path
        rule_path_str = self.config.rule_file or "security/rules/jailbreak.yaml"
        rule_path = Path(rule_path_str)
        if not rule_path.exists():
            # Fallback relative to this file's parent's parent folder
            rule_path = Path(__file__).parent.parent / "rules" / "jailbreak.yaml"

        self._compiled_rules: list[dict[str, Any]] = self._load_and_compile_rules(rule_path)

    def detect(self, prompt: str, context: dict[str, Any] | None = None) -> DetectionResult:
        """
        Scans normalized prompt text against compiled YAML jailbreak rule definitions.

        Args:
            prompt: The normalized prompt text.
            context: Correlation and session metadata.

        Returns:
            DetectionResult: Telemetry results returned from scanning.

        Raises:
            DetectorExecutionError: For unrecoverable runtime crashes.
        """
        request_id = context.get("request_id", "unknown") if context else "unknown"
        start_time = time.perf_counter()

        # 1. Validate detector enabled state
        if not self.config.enabled:
            return DetectionResult(
                request_id=request_id,
                detector_name=self.detector_name,
                threat_type=ThreatType.NONE,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=0.0,
                matched_text="",
                evidence="Detector disabled in configuration.",
                execution_time_ms=0.0,
                status=DetectionStatus.SKIPPED,
                timestamp=self._current_timestamp(),
                metadata={}
            )

        try:
            matches: list[dict[str, Any]] = []

            # Execute matching strategy across rules
            for rule in self._compiled_rules:
                if not rule.get("enabled", True):
                    continue

                matched_text = ""
                matched_pattern = ""
                match_count = 0

                # 3. Execute regex matching
                rx_text, rx_pat, rx_count = self._regex_match(prompt, rule)
                if rx_count > 0:
                    matched_text = rx_text
                    matched_pattern = rx_pat
                    match_count += rx_count

                # 4. Execute keyword matching
                kw_text, kw_pat, kw_count = self._keyword_match(prompt, rule)
                if kw_count > 0:
                    match_count += kw_count
                    if not matched_text:
                        matched_text = kw_text
                        matched_pattern = kw_pat

                # 5. Execute phrase matching
                ph_text, ph_pat, ph_count = self._phrase_match(prompt, rule)
                if ph_count > 0:
                    match_count += ph_count
                    if not matched_text:
                        matched_text = ph_text
                        matched_pattern = ph_pat

                # 6. Aggregate matches
                if match_count > 0:
                    matches.append({
                        "rule_id": rule["rule_id"],
                        "rule_name": rule["rule_name"],
                        "threat_type": rule["threat_type"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "matched_text": matched_text,
                        "matched_pattern": matched_pattern,
                        "match_count": match_count,
                        "category": rule["category"],
                        "priority": rule["priority"],
                        "tags": list(rule["tags"]),
                        "recommendation": rule["recommendation"],
                        "description": rule["description"]
                    })

            # Calculate processing time
            elapsed_time_ms = (time.perf_counter() - start_time) * 1000.0

            # 7. Select highest priority matching rule (lowest number wins)
            winning_match = min(matches, key=lambda x: x["priority"]) if matches else None
            return self._build_detection_result(winning_match, request_id, elapsed_time_ms)

        except (RuleLoadingError, ConfigurationError):
            raise
        except Exception as e:
            # Wrap unexpected system crashes to isolate pipeline errors
            raise DetectorExecutionError(f"Unexpected runtime failure in detector: {e}") from e

    def _regex_match(self, prompt: str, rule: dict[str, Any]) -> tuple[str, str, int]:
        """
        Executes regular expression matching for a given rule.
        """
        matched_text = ""
        matched_pattern = ""
        match_count = 0
        for pattern in rule.get("compiled_patterns", []):
            for match in pattern.finditer(prompt):
                match_count += 1
                if not matched_text:
                    matched_text = match.group(0)
                    matched_pattern = pattern.pattern
        return matched_text, matched_pattern, match_count

    def _keyword_match(self, prompt: str, rule: dict[str, Any]) -> tuple[str, str, int]:
        """
        Executes keyword token matching for a given rule.
        """
        matched_text = ""
        matched_pattern = ""
        match_count = 0
        for kw in rule.get("keywords", []):
            words = re.findall(r"\b\w+\b", prompt.lower())
            if kw.lower() in words:
                match_count += 1
                if not matched_text:
                    matched_text = kw
                    matched_pattern = f"keyword: {kw}"
        return matched_text, matched_pattern, match_count

    def _phrase_match(self, prompt: str, rule: dict[str, Any]) -> tuple[str, str, int]:
        """
        Executes substring phrase matching for a given rule.
        """
        matched_text = ""
        matched_pattern = ""
        match_count = 0
        for phrase in rule.get("phrases", []):
            if phrase.lower() in prompt.lower():
                match_count += 1
                if not matched_text:
                    matched_text = phrase
                    matched_pattern = f"phrase: {phrase}"
        return matched_text, matched_pattern, match_count

    def _build_detection_result(
        self,
        winning_match: dict[str, Any] | None,
        request_id: str,
        elapsed_time_ms: float
    ) -> DetectionResult:
        """
        Constructs the strongly typed DetectionResult object.
        """
        if winning_match is None:
            return DetectionResult(
                request_id=request_id,
                detector_name=self.detector_name,
                threat_type=ThreatType.NONE,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=0.0,
                matched_text="",
                evidence="",
                execution_time_ms=elapsed_time_ms,
                status=DetectionStatus.SUCCESS,
                timestamp=self._current_timestamp(),
                metadata={}
            )

        # Map strings back to strongly typed enums safely
        try:
            threat_enum = ThreatType[winning_match["threat_type"]]
        except KeyError:
            threat_enum = ThreatType.JAILBREAK

        try:
            severity_enum = SeverityLevel[winning_match["severity"]]
        except KeyError:
            severity_enum = SeverityLevel.CRITICAL

        meta = {
            "rule_id": winning_match["rule_id"],
            "rule_name": winning_match["rule_name"],
            "matched_pattern": winning_match["matched_pattern"],
            "match_count": winning_match["match_count"],
            "category": winning_match["category"],
            "priority": winning_match["priority"],
            "tags": winning_match["tags"],
            "recommendation": winning_match["recommendation"]
        }

        evidence = (
            f"Triggered rule '{winning_match['rule_name']}' (ID: {winning_match['rule_id']}). "
            f"Pattern matched: '{winning_match['matched_pattern']}'."
        )

        return DetectionResult(
            request_id=request_id,
            detector_name=self.detector_name,
            threat_type=threat_enum,
            severity=severity_enum,
            confidence=winning_match["confidence"],
            matched_text=winning_match["matched_text"],
            evidence=evidence,
            execution_time_ms=elapsed_time_ms,
            status=DetectionStatus.SUCCESS,
            timestamp=self._current_timestamp(),
            metadata=meta
        )

    def _current_timestamp(self) -> datetime:
        """
        Returns the current timezone-aware timestamp.
        """
        return datetime.now(timezone.utc)

    def _load_and_compile_rules(self, rule_path: Path) -> list[dict[str, Any]]:
        """
        Reads, parses, and validates the external YAML rules database file.
        """
        if not rule_path.exists():
            raise RuleLoadingError(f"Rule database config file not found: {rule_path}")

        try:
            with rule_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise RuleLoadingError(f"Failed to read/parse rule YAML database: {e}") from e

        if not data or "rules" not in data or not isinstance(data["rules"], list):
            raise ConfigurationError("YAML schema error: Missing top-level 'rules' list definition.")

        compiled_rules: list[dict[str, Any]] = []

        for index, rule_def in enumerate(data["rules"]):
            # Validate schema constraints
            required_keys = {
                "rule_id", "rule_name", "description", "enabled", "threat_type",
                "severity", "confidence", "category", "priority", "tags",
                "recommendation", "patterns"
            }
            missing_keys = required_keys - rule_def.keys()
            if missing_keys:
                raise ConfigurationError(
                    f"YAML schema validation failed for rule at index {index}. "
                    f"Missing keys: {missing_keys}"
                )

            # Validate Enum types compatibility
            threat_str = rule_def["threat_type"]
            if threat_str not in ThreatType.__members__:
                raise ConfigurationError(
                    f"Invalid threat_type '{threat_str}' in rule {rule_def['rule_id']}. "
                    f"Allowed: {list(ThreatType.__members__.keys())}"
                )

            severity_str = rule_def["severity"]
            if severity_str not in SeverityLevel.__members__:
                raise ConfigurationError(
                    f"Invalid severity '{severity_str}' in rule {rule_def['rule_id']}. "
                    f"Allowed: {list(SeverityLevel.__members__.keys())}"
                )

            # Validate confidence boundaries
            confidence_val = rule_def["confidence"]
            try:
                conf_float = float(confidence_val)
                if not (0.0 <= conf_float <= 1.0):
                    raise ValueError()
            except ValueError:
                raise ConfigurationError(
                    f"Invalid confidence '{confidence_val}' in rule {rule_def['rule_id']}. "
                    "Must be float between 0.0 and 1.0."
                )

            # Validate priority integer
            priority_val = rule_def["priority"]
            if not isinstance(priority_val, int) or priority_val < 0:
                raise ConfigurationError(
                    f"Invalid priority '{priority_val}' in rule {rule_def['rule_id']}. "
                    "Must be non-negative integer."
                )

            # Compile patterns
            patterns_list = rule_def["patterns"]
            if not isinstance(patterns_list, list):
                raise ConfigurationError(
                    f"Invalid patterns schema in rule {rule_def['rule_id']}. "
                    "Must be list of regex strings."
                )

            compiled_patterns = []
            for pat_str in patterns_list:
                try:
                    compiled_patterns.append(re.compile(pat_str))
                except re.error as e:
                    raise RuleLoadingError(
                        f"Regex compilation failure in rule {rule_def['rule_id']} for pattern '{pat_str}': {e}"
                    ) from e

            # Create rule container
            rule_entry = {
                "rule_id": rule_def["rule_id"],
                "rule_name": rule_def["rule_name"],
                "description": rule_def["description"],
                "enabled": bool(rule_def["enabled"]),
                "threat_type": threat_str,
                "severity": severity_str,
                "confidence": conf_float,
                "category": rule_def["category"],
                "priority": priority_val,
                "tags": rule_def["tags"],
                "recommendation": rule_def["recommendation"],
                "compiled_patterns": compiled_patterns,
                "keywords": rule_def.get("keywords", []),
                "phrases": rule_def.get("phrases", [])
            }
            compiled_rules.append(rule_entry)

        return compiled_rules
