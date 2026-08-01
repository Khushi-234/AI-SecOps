"""
Policy Engine Package for AI-SecOps Framework.

Public API surface for security policy decision evaluation and action enforcement.
"""

from policy_engine.actions import ACTION_PRIORITY, PolicyAction
from policy_engine.config import (
    PolicyEngineConfig,
    ThresholdConfig,
)
from policy_engine.context import RiskContext
from policy_engine.engine import PolicyEngine
from policy_engine.enforcement import EnforcementLayer
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.exceptions import (
    InvalidPolicyInputError,
    PolicyConfigurationError,
    PolicyEngineError,
    PolicyExecutionError,
)
from policy_engine.logger import get_policy_logger, log_policy_decision
from policy_engine.models import PolicyDecision
from policy_engine.rules import (
    AllowRule,
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
    # Actions & Enums
    "PolicyAction",
    # Rules
    "BasePolicyRule",
    "ThreatRule",
    "RiskScoreRule",
    "SeverityRule",
    "AllowRule",
    # Configuration
    "PolicyEngineConfig",
    "ThresholdConfig",
    # Logger
    "get_policy_logger",
    "log_policy_decision",
    # Exceptions
    "PolicyEngineError",
    "InvalidPolicyInputError",
    "PolicyConfigurationError",
    "PolicyExecutionError",
]

