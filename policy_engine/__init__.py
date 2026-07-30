"""
Policy Engine Package for AI-SecOps Framework.

Public API surface for security policy decision evaluation and action enforcement.
"""

from policy_engine.actions import ACTION_PRIORITY, PolicyAction
from policy_engine.config import (
    PolicyEngineConfig,
    SanitizationConfig,
    ThresholdConfig,
)
from policy_engine.context import RiskContext
from policy_engine.engine import PolicyEngine
from policy_engine.enforcement import EnforcementLayer
from policy_engine.enums import SanitizationType
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.exceptions import (
    InvalidPolicyInputError,
    PolicyConfigurationError,
    PolicyEngineError,
    PolicyExecutionError,
    SanitizationError,
)
from policy_engine.logger import get_policy_logger, log_policy_decision
from policy_engine.models import (
    PolicyDecision,
    SanitizationEdit,
    SanitizationResult,
)
from policy_engine.rules import (
    BasePolicyRule,
    RiskScoreRule,
    SeverityRule,
    ThreatRule,
)

__all__ = [
    # Core Facade Orchestrator
    "PolicyEngine",
    # Evaluator & Priority System
    "PolicyEvaluator",
    "ACTION_PRIORITY",
    # Enforcement Layer
    "EnforcementLayer",
    # Context & Models
    "RiskContext",
    "PolicyDecision",
    "SanitizationEdit",
    "SanitizationResult",
    # Actions & Enums
    "PolicyAction",
    "SanitizationType",
    # Rules
    "BasePolicyRule",
    "RiskScoreRule",
    "SeverityRule",
    "ThreatRule",
    # Configuration
    "PolicyEngineConfig",
    "ThresholdConfig",
    "SanitizationConfig",
    # Logger
    "get_policy_logger",
    "log_policy_decision",
    # Exceptions
    "PolicyEngineError",
    "InvalidPolicyInputError",
    "PolicyConfigurationError",
    "SanitizationError",
    "PolicyExecutionError",
]
