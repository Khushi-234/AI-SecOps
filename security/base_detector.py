from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from security.models import DetectionResult


@dataclass(slots=True)
class DetectorConfig:
    """
    Configuration settings for a security detector.

    Holds parameters defining timeout, activation state, threat confidence thresholds,
    rule definition paths, and custom extension parameters.
    """

    enabled: bool = True
    timeout_ms: int = 1000
    threshold: float = 0.5
    rule_file: str = ""
    custom_settings: dict[str, Any] = field(default_factory=dict)


class BaseDetector(ABC):
    """
    Abstract base class establishing the security inspection contract.

    Purpose:
    --------
    Provides a uniform interface (polymorphism) for all pluggable threat
    detectors within the Prompt Firewall's verification pipeline.

    Dependency Inversion (SOLID):
    -----------------------------
    The PromptFirewall orchestrator depends on this BaseDetector abstraction
    rather than any concrete scanner. This allows developer teams to easily
    add, remove, or swap scanner models without altering the pipeline runner code.

    Execution Contract:
    -------------------
    Every concrete detector subclass implementation MUST adhere to these design rules:
    - Pure & Stateless: Must not store dynamic request variables on 'self' or preserve
                        state across inspect operations.
    - Thread-safe: Support concurrent request invocations across multiple execution threads.
    - Side-effect Free: Strictly read-only analysis. The detect() call must NEVER:
        * Modify or sanitize prompt strings.
        * Call external LLMs directly.
        * Communicate with system databases.
        * Log events directly to console/files (telemetry returns to parent orchestrator).
        * Calculate aggregated framework risk index.
        * Make policy decisions (e.g. blocking requests).

    Error Handling Policy:
    ----------------------
    - Recoverable Detector Failures: Trapped internally by the detector, which should
      return a standard DetectionResult with `status = DetectionStatus.ERROR`.
    - Unrecoverable Framework Failures: E.g., system OOM or runtime interpreter failures
      should be bubbled up or raised as `DetectorExecutionError`.

    Extensibility:
    --------------
    Subclasses override `detector_name` as an abstract property to define their identifier,
    and implement `detect()` to execute custom rule, regex, or semantic checks.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        """
        Initializes the detector with a configuration container.

        Args:
            config: Configuration container. Defaults to an empty config if None.
        """
        self.config = config or DetectorConfig()

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """
        Read-only abstract property. Subclasses must override this to return
        their fixed string identifier.
        """
        pass

    @abstractmethod
    def detect(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """
        Inspects the normalized prompt string to identify security violations.

        Args:
            prompt: The normalized user input text.
            context: Correlation and session metadata.

        Returns:
            DetectionResult: Telemetry results returned from scanning.
        """
        pass
