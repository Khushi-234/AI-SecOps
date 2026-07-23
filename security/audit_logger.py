from abc import ABC, abstractmethod
from typing import Any


class AuditLogger(ABC):
    """
    Abstract base interface establishing the auditing and logging contract.

    Dependency Inversion Principle (SOLID):
    The PromptFirewall depends entirely on this abstract AuditLogger interface
    rather than a concrete logging class (such as database, file, or cloud loggers).
    This design decouples high-level policy orchestration from low-level storage
    mechanisms, enabling developers to swap or extend logging implementations
    in future sprints without modifying core firewall verification logic.
    """

    @abstractmethod
    def log_event(
        self, event_type: str, request_id: str, details: dict[str, Any]
    ) -> None:
        """
        Logs a transaction audit event containing execution metadata.

        Args:
            event_type: Category identifier of the event (e.g., "PROMPT_AUDIT", "FIREWALL_ERROR").
            request_id: Core correlation identifier tracing the request lifecycle.
            details: Contextual payload containing the normalized prompt, detector results,
                     and pipeline timings.
        """
        pass
