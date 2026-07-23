class AISECOPSError(Exception):
    """
    Base exception class for all errors within the AI-SecOps Framework.

    All custom framework exceptions should inherit from this root class.
    """

    pass


class ValidationError(AISECOPSError):
    """
    Raised when input validation constraints are violated.

    Common use cases:
    - Input prompt is None.
    - Input prompt is empty or consists purely of whitespace/control characters.
    - Input prompt size exceeds the safety length threshold limits.
    """

    pass


class NormalizationError(AISECOPSError):
    """
    Raised when text normalization processes cannot be completed safely.

    Common use cases:
    - Text contains invalid Unicode code points or unparseable byte structures.
    - Normalization library failures or syntax transformation crashes.
    """

    pass


class DetectorError(AISECOPSError):
    """
    Base exception for errors originating inside detector modules.
    """

    pass


class DetectorExecutionError(DetectorError):
    """
    Raised when a security detector experiences an unrecoverable runtime failure.

    Common use cases:
    - A detector module crashes during pattern matching or computation.
    - An unexpected third-party library failure bubbles out of the detector's inspect logic.
    """

    pass


class RuleLoadingError(AISECOPSError):
    """
    Raised when external detector rule definition sets fail to load.

    Common use cases:
    - The rule file (e.g., security/rules/prompt_injection.yaml) is missing.
    - The rule file content is corrupted or has invalid YAML structure.
    - Configured rule items are missing mandatory properties (like rule_id or patterns).
    """

    pass


class ConfigurationError(AISECOPSError):
    """
    Raised when configuration objects or settings contain invalid configurations.

    Common use cases:
    - Invalid threshold scores (e.g. outside 0.0 to 1.0/10.0 limits).
    - Invalid timeout values or missing parameter properties in configurations.
    """

    pass


class FirewallError(AISECOPSError):
    """
    Raised when the core firewall orchestrator fails.

    Common use cases:
    - Unrecoverable pipeline loop crashes.
    - Pipeline initialization failures.
    """

    pass
