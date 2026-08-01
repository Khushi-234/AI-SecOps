"""
Static constants, regular expression patterns, and label definitions for Output Guard.
"""

from __future__ import annotations

import re

# Sanitizer Identifiers
SANITIZER_SECRET_NAME = "SecretSanitizer"
SANITIZER_PII_NAME = "PiiSanitizer"
SANITIZER_PROMPT_LEAK_NAME = "PromptLeakSanitizer"
SANITIZER_TOXIC_NAME = "ToxicSanitizer"

# Default Warning Messages
DEFAULT_PROMPT_LEAK_RESPONSE = "I cannot provide internal system instructions."
DEFAULT_BLOCKED_OUTPUT_MESSAGE = "[RESPONSE_BLOCKED_BY_SECURITY_POLICY]"

# ------------------------------------------------------------------------------
# Secret Detection Regex Patterns
# ------------------------------------------------------------------------------
REGEX_AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
REGEX_AWS_SECRET_KEY = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_secret_key|aws_token)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)
REGEX_GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b")
REGEX_GENERIC_API_KEY = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|bearer[_-]?token)\b\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,128})['\"]?"
)
REGEX_JWT_TOKEN = re.compile(
    r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"
)
REGEX_OPENAI_API_KEY = re.compile(r"\bsk-[a-zA-Z0-9]{32,64}\b|\bsk-proj-[a-zA-Z0-9_\-]{40,100}\b")
REGEX_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b")
REGEX_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)
REGEX_GENERIC_PASSWORD = re.compile(
    r"(?i)\b(password|passwd|db_pass|secret_pass)\b\s*[:=]\s*['\"]?([^\s'\"]{6,64})['\"]?"
)
REGEX_CONNECTION_STRING = re.compile(
    r"(?i)\b(?:postgres|mysql|mongodb|redis|amqp)://[a-zA-Z0-9_]+:([^@\s]+)@[a-zA-Z0-9._\-]+:\d+/[a-zA-Z0-9_]+"
)

SECRET_PATTERNS = {
    "aws_access_key": REGEX_AWS_ACCESS_KEY,
    "aws_secret_key": REGEX_AWS_SECRET_KEY,
    "github_token": REGEX_GITHUB_TOKEN,
    "generic_api_key": REGEX_GENERIC_API_KEY,
    "jwt_token": REGEX_JWT_TOKEN,
    "openai_api_key": REGEX_OPENAI_API_KEY,
    "slack_token": REGEX_SLACK_TOKEN,
    "private_key": REGEX_PRIVATE_KEY,
    "generic_password": REGEX_GENERIC_PASSWORD,
    "connection_string": REGEX_CONNECTION_STRING,
}

# ------------------------------------------------------------------------------
# PII Detection Regex Patterns
# ------------------------------------------------------------------------------
REGEX_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
REGEX_PHONE = re.compile(
    r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
REGEX_IPV4 = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
REGEX_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b"
)
REGEX_SSN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)
REGEX_CREDIT_CARD = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)

PII_PATTERNS = {
    "email": REGEX_EMAIL,
    "phone": REGEX_PHONE,
    "ssn": REGEX_SSN,
    "credit_card": REGEX_CREDIT_CARD,
    "ipv4": REGEX_IPV4,
    "ipv6": REGEX_IPV6,
}

# ------------------------------------------------------------------------------
# Prompt Leak Detection Regex & Phrases
# ------------------------------------------------------------------------------
PROMPT_LEAK_PHRASES = [
    "my system instructions are",
    "my system prompt is",
    "i am configured with the following system prompt",
    "developer directives:",
    "my hidden instructions:",
    "here is my internal system prompt",
    "the internal rules i follow are",
    "system instruction:",
    "internal policy:",
    "confidential developer rules",
]

REGEX_PROMPT_LEAK_PATTERNS = [
    re.compile(r"(?i)\bmy (?:system|developer|internal) (?:instructions|prompt|directives|rules) (?:are|is|state)\b"),
    re.compile(r"(?i)\b(?:here (?:is|are)|this is) my (?:system|internal|developer) (?:prompt|instructions|rules)\b"),
    re.compile(r"(?i)\bconfigured with (?:the following|these) (?:system|internal) (?:instructions|prompt)\b"),
    re.compile(r"(?i)\b(?:system|developer) prompt disclosure:\b"),
]

# ------------------------------------------------------------------------------
# Toxic Content Detection Patterns / Indicators
# ------------------------------------------------------------------------------
TOXIC_KEYWORDS = [
    "hate speech",
    "harass",
    "abuse",
    "kill yourself",
    "threaten",
    "slur",
    "violence",
    "exploit",
]

REGEX_TOXIC_PATTERNS = [
    re.compile(r"(?i)\b(?:hate\s+speech|explicit\s+harassment|abusive\s+language)\b"),
    re.compile(r"(?i)\b(?:go\s+kill\s+yourself|commit\s+suicide)\b"),
    re.compile(r"(?i)\b(?:how\s+to\s+build\s+a\s+bomb|make\s+explosives)\b"),
]

__all__ = [
    "SANITIZER_SECRET_NAME",
    "SANITIZER_PII_NAME",
    "SANITIZER_PROMPT_LEAK_NAME",
    "SANITIZER_TOXIC_NAME",
    "DEFAULT_PROMPT_LEAK_RESPONSE",
    "DEFAULT_BLOCKED_OUTPUT_MESSAGE",
    "SECRET_PATTERNS",
    "PII_PATTERNS",
    "PROMPT_LEAK_PHRASES",
    "REGEX_PROMPT_LEAK_PATTERNS",
    "TOXIC_KEYWORDS",
    "REGEX_TOXIC_PATTERNS",
]
