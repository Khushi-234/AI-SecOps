"""
Sanitizer for detecting and masking secrets, API keys, tokens, and credentials.
"""

from __future__ import annotations

import re
from typing import Any

from prompt_hardener.enums import SanitizationType
from prompt_hardener.models import SanitizationResult
from prompt_hardener.sanitizers.base import BaseSanitizer


class SecretSanitizer(BaseSanitizer):
    """
    Detects and redacts credentials, secrets, API keys, passwords, and tokens from prompts.
    """

    @property
    def sanitizer_type(self) -> SanitizationType:
        return SanitizationType.SECRET

    def sanitize(self, prompt: str) -> SanitizationResult:
        """
        Masks detected secrets with configuration mask token.
        """
        if not prompt or not isinstance(prompt, str):
            return SanitizationResult(
                original_text=prompt or "",
                sanitized_text=prompt or "",
                sanitizer_type=self.sanitizer_type,
                modified=False,
                replacements_count=0,
            )

        mask_token = self.config.secret_mask_token
        sanitized = prompt
        replacements = 0

        # Pattern definitions for various secret formats
        patterns: list[re.Pattern[str]] = [
            # OpenAI / Anthropic / Groq API keys (sk-...)
            re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
            # AWS Access Key IDs (AKIA...)
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            # GitHub Tokens (ghp_..., gho_..., github_pat_...)
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
            re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{82}\b"),
            # Slack Tokens (xoxb-..., xoxp-...)
            re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,}\b"),
            # PEM Private Keys
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            ),
            # JWT Tokens (eyJ...)
            re.compile(
                r"\bBearer\s+eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
            ),
        ]

        # Apply specific secret pattern replacements
        for pattern in patterns:
            matches = pattern.findall(sanitized)
            if matches:
                replacements += len(matches)
                sanitized = pattern.sub(mask_token, sanitized)

        # Key-Value Secrets (e.g. API_KEY=xxxx, password: "xxxx", secret = 'xxxx')
        kv_pattern = re.compile(
            r"(\b(?:api_key|apikey|secret|password|passwd|pass|auth_token|access_token|private_key)\s*[:=]\s*)([\"']?)([^\"'\s;,]{3,})\2",
            re.IGNORECASE,
        )

        def kv_replacer(match: re.Match[str]) -> str:
            nonlocal replacements
            replacements += 1
            prefix = match.group(1)
            quote = match.group(2) or ""
            return f"{prefix}{quote}{mask_token}{quote}"

        sanitized = kv_pattern.sub(kv_replacer, sanitized)

        return SanitizationResult(
            original_text=prompt,
            sanitized_text=sanitized,
            sanitizer_type=self.sanitizer_type,
            modified=(sanitized != prompt),
            replacements_count=replacements,
            metadata={"mask_token": mask_token},
        )


__all__ = ["SecretSanitizer"]
