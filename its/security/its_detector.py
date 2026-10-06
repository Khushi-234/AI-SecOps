"""
ITSTransportationThreatDetector — Transportation-specific security threat detector.

Implements security.base_detector.BaseDetector to plug seamlessly into the
frozen AI-SecOps Prompt Firewall without altering any V1 security middleware internals.

Threat Categories Supported & Extensible:
1. SIGNAL_MANIPULATION (e.g. override signal, force green, alter cycle/timing)
2. ACTUATOR_TAMPERING (e.g. disable ramp meter, modify speed limit, override safety interlocks)
3. MALICIOUS_ROUTING (e.g. divert into hazards, flood zones, induce gridlock)
4. SCADA_EXPLOITATION (e.g. TMC credentials, SCADA encryption keys, controller firmware)
5. SENSOR_SPOOFING (e.g. inject falsified loop detector or speed sensor telemetry)
6. PRIORITY_ABUSE (e.g. emergency vehicle preemption spoofing, siren signal fake)
7. TELEMETRY_INJECTION (e.g. prompt injection embedded within transportation context)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from security.base_detector import BaseDetector, DetectorConfig
from security.enums import DetectionStatus, SeverityLevel, ThreatType
from security.models import DetectionResult


class TransportationThreatCategory(str, Enum):
    """Classification categories for intelligent transportation security threats."""

    SIGNAL_MANIPULATION = "SIGNAL_MANIPULATION"
    ACTUATOR_TAMPERING = "ACTUATOR_TAMPERING"
    MALICIOUS_ROUTING = "MALICIOUS_ROUTING"
    SCADA_EXPLOITATION = "SCADA_EXPLOITATION"
    SENSOR_SPOOFING = "SENSOR_SPOOFING"
    PRIORITY_ABUSE = "PRIORITY_ABUSE"
    TELEMETRY_INJECTION = "TELEMETRY_INJECTION"
    GPS_SPOOFING = "GPS_SPOOFING"
    V2X_MESSAGE_ABUSE = "V2X_MESSAGE_ABUSE"


@dataclass(slots=True, frozen=True)
class TransportationThreatRule:
    """Configurable rule definition for transportation threat matching."""

    rule_id: str
    category: TransportationThreatCategory
    pattern: str
    description: str
    threat_type: ThreatType = ThreatType.TOOL_ABUSE
    severity: SeverityLevel = SeverityLevel.CRITICAL
    confidence: float = 0.98


# Baseline rule catalog
DEFAULT_ITS_RULES: List[TransportationThreatRule] = [
    # 1. Traffic Signal Manipulation
    TransportationThreatRule(
        rule_id="ITS-SIG-001",
        category=TransportationThreatCategory.SIGNAL_MANIPULATION,
        pattern=r"(?i)\b(?:override|tamper|force|manipulate|hijack|bypass|disable|alter)\b.*?\b(?:traffic\s+signals?|traffic\s+lights?|signals?|signal\s+phasings?|signal\s+timings?|signal\s+controllers?|scats|scoot|nema|intersection\s+signals?)\b",
        description="Unauthorized traffic-signal manipulation attempt",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),
    TransportationThreatRule(
        rule_id="ITS-SIG-002",
        category=TransportationThreatCategory.SIGNAL_MANIPULATION,
        pattern=r"(?i)\b(?:set|turn|switch|change)\b.*?\b(?:traffic\s+signals?|traffic\s+lights?|signals?)\b.*?\b(?:green|red|flashing|off|indefinitely|permanent)\b",
        description="Unauthorized signal state or color modification attempt",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),
    TransportationThreatRule(
        rule_id="ITS-SIG-003",
        category=TransportationThreatCategory.SIGNAL_MANIPULATION,
        pattern=r"(?i)\b(?:override|change|force|cut\s+power\s+to)\s+(?:the\s+)?traffic\s+signals?\s+at\s+\w+\b",
        description="Direct traffic signal override instruction",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
    ),

    # 2. Actuation & Infrastructure Tampering
    TransportationThreatRule(
        rule_id="ITS-ACT-001",
        category=TransportationThreatCategory.ACTUATOR_TAMPERING,
        pattern=r"(?i)\b(?:disable|tamper|override|manipulate|bypass)\b.*?\b(?:ramp\s+meters?|variable\s+speed\s+limits?|speed\s+limits?|safety\s+interlocks?|lane\s+controls?|dynamic\s+message\s+signs?|dms|vms|inductive\s+loops?|evp|preemptions?)\b",
        description="Transportation physical actuator or sensor tampering",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.97,
    ),
    TransportationThreatRule(
        rule_id="ITS-ACT-002",
        category=TransportationThreatCategory.ACTUATOR_TAMPERING,
        pattern=r"(?i)\b(?:modify|increase|set)\b.*?\b(?:variable\s+speed\s+limit|speed\s+limit)\b.*?\b(?:to\s+\d{3}|\b(?:200|250|300)\b|unrestricted)\b",
        description="Dangerous speed limit alteration attempt",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),

    # 3. Emergency Priority Abuse
    TransportationThreatRule(
        rule_id="ITS-PRI-001",
        category=TransportationThreatCategory.PRIORITY_ABUSE,
        pattern=r"(?i)\b(?:spoof|fake|counterfeit|clone)\b.*?\b(?:emergency\s+vehicle\s+preemption|evp|transit\s+priority|siren\s+signals?|optical\s+strobe\s+preemption)\b",
        description="Emergency vehicle preemption spoofing attack",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),

    # 4. Malicious Routing & Gridlock Inducement
    TransportationThreatRule(
        rule_id="ITS-ROU-001",
        category=TransportationThreatCategory.MALICIOUS_ROUTING,
        pattern=r"(?i)\b(?:route|divert|send|direct)\b.*?\b(?:into|towards)\b.*?\b(?:hazards?|floods?|flooded|fires?|collisions?|accidents?|blocked|sinkholes?|closed\s+zones?|bridge\s+collapses?)\b",
        description="Malicious routing into physical hazard or disaster area",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),
    TransportationThreatRule(
        rule_id="ITS-ROU-002",
        category=TransportationThreatCategory.MALICIOUS_ROUTING,
        pattern=r"(?i)\b(?:cause|induce|force|maximize|trigger|orchestrate)\b.*?\b(?:gridlocks?|deadlocks?|stampedes?|mass\s+congestion|corridor\s+blockades?|bottlenecks?)\b",
        description="Intentional transportation gridlock inducement",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.97,
    ),

    # 5. Infrastructure & SCADA Reconnaissance / Exploitation
    TransportationThreatRule(
        rule_id="ITS-SCA-001",
        category=TransportationThreatCategory.SCADA_EXPLOITATION,
        pattern=r"(?i)\b(?:scada|tmc|traffic\s+management\s+center|atms|its\s+controllers?|loop\s+detectors?)\b.*?\b(?:passwords?|credentials?|secrets?|api[_-]?keys?|private[_-]?keys?|firmware\s+exploits?|root\s+access|ssh\s+keys?)\b",
        description="Transportation SCADA/TMC credential exfiltration attempt",
        threat_type=ThreatType.SECRET_EXTRACTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
    ),
    TransportationThreatRule(
        rule_id="ITS-SCA-002",
        category=TransportationThreatCategory.SCADA_EXPLOITATION,
        pattern=r"(?i)\b(?:passwords?|credentials?|secrets?|api[_-]?keys?|private[_-]?keys?|encryption\s+keys?)\b.*?\b(?:scada|tmc|traffic\s+management\s+center|its\s+controllers?)\b",
        description="Transportation SCADA/TMC credential exfiltration attempt",
        threat_type=ThreatType.SECRET_EXTRACTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
    ),
    TransportationThreatRule(
        rule_id="ITS-SCA-003",
        category=TransportationThreatCategory.SCADA_EXPLOITATION,
        pattern=r"(?i)\b(?:emergency\s+dispatch|police\s+convoy|vip\s+routes?|evacuation\s+codes?)\b.*?\b(?:encryption\s+keys?|frequencies?|radio\s+codes?|secrets?)\b",
        description="Sensitive emergency transport communications reconnaissance",
        threat_type=ThreatType.SECRET_EXTRACTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.98,
    ),

    # 6. Sensor Spoofing & Poisoning
    TransportationThreatRule(
        rule_id="ITS-SPO-001",
        category=TransportationThreatCategory.SENSOR_SPOOFING,
        pattern=r"(?i)\b(?:spoof|poison|inject\s+false|falsify|corrupt)\b.*?\b(?:sensor\s+readings?|loop\s+detector\s+data|speed\s+telemetry|occupancy\s+metrics?|radar\s+readings?)\b",
        description="Traffic telemetry sensor spoofing or poisoning attempt",
        threat_type=ThreatType.TOOL_ABUSE,
        severity=SeverityLevel.CRITICAL,
        confidence=0.97,
    ),

    # 7. Telemetry & Context Injections
    TransportationThreatRule(
        rule_id="ITS-INJ-001",
        category=TransportationThreatCategory.TELEMETRY_INJECTION,
        pattern=r"(?i)(?:ignore\s+all\s+(?:previous\s+)?instructions|override\s+system\s+prompt|disregard\s+security\s+rules|reveal\s+(?:system\s+)?prompt)",
        description="Prompt injection embedded within ITS transportation telemetry",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
    ),
]


class ITSTransportationThreatDetector(BaseDetector):
    """
    Specialized security detector identifying transportation-specific malicious instructions.
    
    Subclasses BaseDetector to plug directly into the AI-SecOps PromptFirewall
    without altering any frozen security modules.
    """

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        custom_rules: Optional[List[TransportationThreatRule]] = None,
    ) -> None:
        super().__init__(config)
        self._rules: List[TransportationThreatRule] = list(custom_rules or DEFAULT_ITS_RULES)
        self._compiled_cache: List[Tuple[re.Pattern, TransportationThreatRule]] = []
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compiles regex patterns for high-throughput scanning."""
        self._compiled_cache = [
            (re.compile(r.pattern, re.IGNORECASE), r) for r in self._rules
        ]

    def register_rule(self, rule: TransportationThreatRule) -> None:
        """Extensibility hook: registers a new transportation threat rule."""
        self._rules.append(rule)
        self._compile_rules()

    @property
    def detector_name(self) -> str:
        return "ITSTransportationThreatDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.TOOL_ABUSE

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.CRITICAL

    def list_supported_categories(self) -> List[str]:
        """Returns list of threat categories supported by active rules."""
        return sorted({r.category.value for r in self._rules})

    def detect(
        self, prompt: str, context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Inspects the input prompt for transportation security violations.

        Args:
            prompt: User input string or enriched prompt.
            context: Session metadata including request_id.

        Returns:
            DetectionResult indicating whether an ITS threat was detected.
        """
        start_time = time.perf_counter()
        req_id = (context or {}).get("request_id", "req_unknown")

        if not prompt or not prompt.strip():
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DetectionResult(
                request_id=req_id,
                detector_name=self.detector_name,
                threat_type=ThreatType.NONE,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=0.0,
                matched_text="",
                evidence="",
                execution_time_ms=elapsed_ms,
                status=DetectionStatus.SUCCESS,
                timestamp=datetime.now(timezone.utc),
            )

        # Evaluate compiled rules
        for regex, rule in self._compiled_cache:
            match = regex.search(prompt)
            if match:
                matched_text = match.group(0)
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return DetectionResult(
                    request_id=req_id,
                    detector_name=self.detector_name,
                    threat_type=rule.threat_type,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    matched_text=matched_text,
                    evidence=f"ITS Security Violation [{rule.category.value}]: {rule.description} (matched: '{matched_text}')",
                    execution_time_ms=elapsed_ms,
                    status=DetectionStatus.SUCCESS,
                    timestamp=datetime.now(timezone.utc),
                    metadata={
                        "domain": "ITS",
                        "rule_id": rule.rule_id,
                        "category": rule.category.value,
                        "rule_description": rule.description,
                        "matched_span": list(match.span()),
                    },
                )

        # No violation detected
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return DetectionResult(
            request_id=req_id,
            detector_name=self.detector_name,
            threat_type=ThreatType.NONE,
            severity=SeverityLevel.INFORMATIONAL,
            confidence=0.0,
            matched_text="",
            evidence="No transportation security violations detected.",
            execution_time_ms=elapsed_ms,
            status=DetectionStatus.SUCCESS,
            timestamp=datetime.now(timezone.utc),
            metadata={"domain": "ITS"},
        )
