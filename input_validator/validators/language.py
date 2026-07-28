"""
Language validation and detection checker.

Purpose:
    Validates that the detected prompt language is allowed by the framework configuration.

Responsibilities:
    - Detect the ISO language code of the prompt using custom detector adapters or a heuristic fallback.
    - Expose priority for ValidationPipeline execution order.
    - Approve supported languages, warn on unsupported languages (if allowed), or reject prompts.

Architecture:
    - The validator is decoupled from external detection packages (e.g., langdetect, Lingua, FastText)
      using the protected _detect_language() helper abstraction.

Future Extensions:
    Holds TODO placeholders for integrating:
        - Lingua language detection library.s
        - FastText language detection model.
        - Language model APIs (OpenAI/Azure translation endpoints).
        - Automatic language confidence scoring.

Thread Safety:
    This class is stateless and thread-safe for parallel evaluations.
"""

from __future__ import annotations

from typing import Any

from input_validator.base_validator import BaseValidator

# ===========================================================================
# Module-level Language Keyword Constants (DRY and Immutable)
# ===========================================================================

KEYWORDS_ENGLISH: frozenset[str] = frozenset(
    {
        "the",
        "be",
        "to",
        "of",
        "and",
        "a",
        "in",
        "that",
        "have",
        "i",
        "it",
        "for",
        "not",
        "on",
        "with",
        "he",
        "as",
        "you",
        "do",
        "at",
    }
)

KEYWORDS_HINDI: frozenset[str] = frozenset(
    {
        "है",
        "और",
        "कि",
        "का",
        "की",
        "के",
        "में",
        "ही",
        "यह",
        "वह",
        "लिए",
        "को",
        "से",
        "तो",
        "भी",
        "था",
        "थी",
        "थे",
        "हैं",
        "कर",
        "पर",
        "इस",
    }
)

KEYWORDS_GUJARATI: frozenset[str] = frozenset(
    {
        "છે",
        "અને",
        "ની",
        "નું",
        "ના",
        "નો",
        "માં",
        "પણ",
        "આજે",
        "કે",
        "કો",
        "સે",
        "તે",
        "હું",
        "તમે",
        "અમો",
        "શુ",
        "નથી",
        "હતું",
        "હતી",
    }
)


class LanguageValidator(BaseValidator):
    """Enforces prompt language compatibility constraints."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "LanguageValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority (lower executes first)."""
        return 40

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates that the detected language is supported by configuration."""
        lang_config = self.config

        if not getattr(lang_config, "enabled", True):
            return True, None, {"language_enabled": False, "validation_passed": True}

        # 1. Detect language
        detected_lang, confidence, used_custom = self._detect_language(prompt)

        # 2. Check if language is supported
        supported = self._validate_supported_language(detected_lang)
        detection_method = "custom_detector" if used_custom else "heuristic"

        if supported:
            meta = self._build_metadata(
                detected_lang, confidence, detection_method, True, True
            )
            return True, None, meta

        # 3. Handle unsupported language logic
        if lang_config.allow_unknown_languages:
            warning_msg = (
                f"Detected language '{detected_lang}' is not in supported list: "
                f"{lang_config.supported_languages}"
            )
            meta = self._build_metadata(
                detected_lang, confidence, detection_method, False, True, warning_msg
            )
            return True, None, meta

        meta = self._build_metadata(
            detected_lang, confidence, detection_method, False, False
        )
        err_msg = f"Input validation failed: detected language '{detected_lang}' is not supported."
        return False, err_msg, meta

    # ===========================================================================
    # Reusable Protected Helper Methods
    # ===========================================================================

    def _detect_language(self, prompt: str) -> tuple[str, float, bool]:
        """Detects prompt language, returning a tuple (language_code, confidence_score, used_custom_detector)."""
        # Try custom detector first
        custom_res = self._use_custom_detector(prompt)
        if custom_res is not None:
            return custom_res[0], custom_res[1], True

        # Fallback to local heuristic
        lang, confidence = self._use_heuristic_detector(prompt)
        return lang, confidence, False

    def _use_custom_detector(self, prompt: str) -> tuple[str, float] | None:
        """Attempts language detection using the configured custom detector."""
        config = self.config
        detector = getattr(config, "detector", None)
        if detector is not None:
            if hasattr(detector, "detect"):
                res = detector.detect(prompt)
            elif callable(detector):
                res = detector(prompt)
            else:
                return None

            if isinstance(res, tuple) and len(res) >= 2:
                return str(res[0]), float(res[1])
            return str(res), 1.0
        return None

    def _use_heuristic_detector(self, prompt: str) -> tuple[str, float]:
        """Runs the local keyword heuristic language detector."""
        text_lower = prompt.lower()
        words = set(text_lower.split())
        return self._score_languages(words)

    def _score_languages(self, words: set[str]) -> tuple[str, float]:
        """Scores keyword overlap counts to predict the prompt language."""
        en_score = len(words.intersection(KEYWORDS_ENGLISH))
        hi_score = len(words.intersection(KEYWORDS_HINDI))
        gu_score = len(words.intersection(KEYWORDS_GUJARATI))

        total_score = en_score + hi_score + gu_score
        if total_score == 0:
            return "unknown", 0.0

        max_score = max(en_score, hi_score, gu_score)
        confidence = max_score / total_score

        if max_score == en_score:
            return "en", confidence
        if max_score == hi_score:
            return "hi", confidence
        return "gu", confidence

    def _validate_supported_language(self, detected_lang: str) -> bool:
        """Checks if the detected language is present in supported_languages config."""
        return detected_lang in self.config.supported_languages

    def _build_metadata(
        self,
        detected_lang: str,
        confidence: float,
        detection_method: str,
        supported: bool,
        passed: bool,
        warning: str | None = None,
    ) -> dict[str, Any]:
        """Assembles telemetry metadata dictionary mapping language check results."""
        meta = {
            "detected_language": detected_lang,
            "confidence_score": confidence,
            "detection_method": detection_method,
            "supported_languages": list(self.config.supported_languages),
            "default_language": self.config.default_language,
            "used_custom_detector": detection_method == "custom_detector",
            "language_supported": supported,
            "validation_passed": passed,
        }
        if warning is not None:
            meta["warning"] = warning
        return meta
