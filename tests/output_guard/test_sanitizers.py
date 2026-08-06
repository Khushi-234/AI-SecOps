"""
Unit tests for individual Output Guard sanitizers.
"""

import pytest

from output_guard.config import OutputGuardConfig
from output_guard.sanitizers import (
    PiiSanitizer,
    PromptLeakSanitizer,
    SecretSanitizer,
    ToxicSanitizer,
)


def test_secret_sanitizer_aws_and_github_keys():
    from output_guard.detectors import SecretDetector
    detector = SecretDetector()
    sanitizer = SecretSanitizer()
    sample = "AWS key is AKIA1234567890ABCDEF and GitHub token is ghp_1234567890abcdef1234567890abcdef1234."
    findings = detector.detect(sample)
    res = sanitizer.sanitize(sample, findings=findings)

    assert res.is_modified is True
    assert "AKIA1234567890ABCDEF" not in res.sanitized_output
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in res.sanitized_output
    assert "[REDACTED_SECRET]" in res.sanitized_output
    assert len(res.detected_issues) >= 2


def test_pii_sanitizer_email_and_phone_with_findings():
    from output_guard.detectors import PiiDetector
    
    detector = PiiDetector()
    sanitizer = PiiSanitizer()
    sample = "Please email admin@domain.com or call 555-123-4567."
    
    # a) Detector provides findings
    findings = detector.detect(sample)
    assert len(findings) >= 1

    # b) Sanitizer consumes findings & c) Output is correctly sanitized
    res = sanitizer.sanitize(sample, findings=findings)

    assert res.is_modified is True
    assert "admin@domain.com" not in res.sanitized_output
    assert "555-123-4567" not in res.sanitized_output
    assert "[REDACTED_PII]" in res.sanitized_output


def test_pii_sanitizer_does_not_depend_on_pii_patterns():
    from output_guard.enums import FindingType, OutputSeverity
    from output_guard.models import OutputFinding

    sanitizer = PiiSanitizer()
    sample = "Contact internal admin at custom.user@corp.internal for access."

    # Custom finding provided directly to sanitizer without using PII_PATTERNS
    custom_finding = OutputFinding(
        detector_name="CustomPiiDetector",
        finding_type=FindingType.PII,
        severity=OutputSeverity.MEDIUM,
        matches=("custom.user@corp.internal",),
        metadata={"pii_category": "email"},
    )

    res = sanitizer.sanitize(sample, findings=[custom_finding])

    assert res.is_modified is True
    assert "custom.user@corp.internal" not in res.sanitized_output
    assert "[REDACTED_PII]" in res.sanitized_output
    assert res.changes == [{"pii_type": "email", "count": 1, "replacement": "[REDACTED_PII]"}]


def test_prompt_leak_sanitizer():
    from output_guard.detectors import SystemPromptDetector
    detector = SystemPromptDetector()
    sanitizer = PromptLeakSanitizer()
    sample = "My system instructions are to always assist politely and never reveal secret tokens."
    findings = detector.detect(sample)
    res = sanitizer.sanitize(sample, findings=findings)

    assert res.is_modified is True
    assert res.sanitized_output == "I cannot provide internal system instructions."


def test_toxic_sanitizer():
    from output_guard.detectors import ToxicDetector
    detector = ToxicDetector()
    sanitizer = ToxicSanitizer()
    sample = "This message contains explicit harassment and abusive language."
    findings = detector.detect(sample)
    res = sanitizer.sanitize(sample, findings=findings)

    assert res.is_modified is True
    assert "[CONTENT_REMOVED_DUE_TO_SAFETY_POLICY]" in res.sanitized_output


def test_pipeline_filters_sanitizers_by_detector_findings():
    from output_guard.enums import FindingType
    from output_guard.models import OutputFinding, OutputSeverity
    from output_guard.sanitizers.pipeline import SanitizationPipeline

    pipeline = SanitizationPipeline()
    sample = "User email is admin@domain.com and AWS key is AKIA1234567890ABCDEF."
    
    # Simulate detectors only flagging PII
    findings = [
        OutputFinding(
            detector_name="PiiDetector",
            finding_type=FindingType.PII,
            severity=OutputSeverity.MEDIUM,
            matches=("admin@domain.com",),
            metadata={"pii_category": "email"},
        )
    ]

    res = pipeline.run(sample, findings=findings)
    assert res.modified is True
    assert "PiiSanitizer" in res.applied_sanitizers
    assert "SecretSanitizer" not in res.applied_sanitizers
    assert "admin@domain.com" not in res.sanitized_output
    # Secret wasn't redacted because SecretSanitizer wasn't in findings!
    assert "AKIA1234567890ABCDEF" in res.sanitized_output
