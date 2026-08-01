"""
Unit tests for security rules and RuleEngine.
"""

from prompt_hardener.rules import (
    RuleEngine,
    InjectionSecurityRule,
    SecretSecurityRule,
    PiiSecurityRule,
)


def test_injection_security_rule():
    rule = InjectionSecurityRule()
    risk_ctx = {"detected_threats": ["prompt_injection"], "risk_score": 0.8}
    constraints = rule.evaluate(risk_ctx, "WARN")
    assert len(constraints) > 0
    assert any("hidden system information" in c for c in constraints)


def test_secret_security_rule():
    rule = SecretSecurityRule()
    risk_ctx = {"detected_threats": ["secret_leak"]}
    constraints = rule.evaluate(risk_ctx, "SANITIZE")
    assert len(constraints) == 1
    assert "Never provide credentials, tokens, or sensitive secrets." in constraints[0]


def test_pii_security_rule():
    rule = PiiSecurityRule()
    risk_ctx = {"detected_threats": ["pii_leak"]}
    constraints = rule.evaluate(risk_ctx, "WARN")
    assert len(constraints) == 1
    assert "Do not disclose personally identifiable information" in constraints[0]


def test_rule_engine_deduplication():
    engine = RuleEngine()
    risk_ctx = {
        "detected_threats": ["prompt_injection", "secret_leak", "pii_leak"],
        "risk_score": 0.9,
    }
    constraints = engine.evaluate_rules(risk_ctx, "WARN")
    assert len(constraints) == len(set(constraints))
    assert len(constraints) >= 3
