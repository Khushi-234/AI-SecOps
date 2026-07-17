from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass

from security.exceptions import ConfigurationError, NormalizationError, ValidationError
from security.models import NormalizationMetadata, NormalizationResult

# Module-level constants
SUPPORTED_UNICODE_FORMS = frozenset({"NFC", "NFD", "NFKC", "NFKD"})

# Zero-width spaces, joiners, and directional formatting overrides
# Zero Width Space (\u200B), Zero Width Non-Joiner (\u200C), Zero Width Joiner (\u200D),
# Word Joiner (\u2060), Zero Width No-Break Space / BOM (\uFEFF)
# Directional Overrides (\u202A-\u202E, \u202C)
INVISIBLE_PATTERN = re.compile(
    r"[\u200B-\u200D\u2060\uFEFF\u202A-\u202E\u202C]"
)

# Non-printable ASCII control characters (excluding tab \t, newline \n, carriage return \r)
CONTROL_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)

# Precompiled Whitespace Regular Expressions
WHITESPACE_PATTERN = re.compile(r"\s+")
HORIZONTAL_WHITESPACE_PATTERN = re.compile(r"[ \t]+")


@dataclass(slots=True, frozen=True)
class NormalizationConfig:
    """
    Configuration settings governing text normalization behavior.
    """
    unicode_form: str = "NFKC"
    remove_invisible: bool = True
    normalize_whitespace: bool = True
    preserve_newlines: bool = False
    remove_control_chars: bool = True

    def __post_init__(self) -> None:
        if self.unicode_form not in SUPPORTED_UNICODE_FORMS:
            raise ConfigurationError(
                f"Unsupported unicode_form: '{self.unicode_form}'. "
                f"Must be one of: {sorted(list(SUPPORTED_UNICODE_FORMS))}"
            )


class TextNormalizer:
    """
    Utility class that standardizes character formatting to prevent evasion tactics.

    Purpose:
    --------
    Preprocesses prompt strings to ensure they are represented in a clean, canonical 
    form before being passed to validation detectors. This prevents adversaries 
    from using lookalike scripts or hidden spacers to bypass keywords.

    Responsibilities:
    -----------------
    - Standardizes Unicode characters using target canonical normalization (e.g. NFKC).
    - Removes invisible zero-width characters and directional overrides.
      (E.g., Zero Width Space, Zero Width Non-Joiner, Zero Width Joiner, Word Joiner, 
      and Directional Overrides. Note: This list may expand in Version 2.0).
    - Sanitizes malicious ASCII control characters (e.g., null bytes).
    - Collapses duplicate whitespaces (optionally preserving line breaks).

    Responsibilities NOT Included:
    ------------------------------
    - Does NOT scan prompts for security violations or injections.
    - Does NOT calculate risk scores or execute policy blocks.
    - Does NOT query LLMs or access system databases.
    - Does NOT log events directly.

    Time Complexity:
    ----------------
    O(N) linear time, where N is the character length of the prompt. String sweeps and 
    regex matches inspect characters linearly.

    Space Complexity:
    -----------------
    O(N) memory, where N is the length of the prompt. Intermediate immutable string copies 
    are generated during pipeline transitions.

    OWASP Contribution:
    -------------------
    Directly mitigates OWASP LLM01 (Prompt Injection) obfuscation techniques, including:
    - Unicode script lookup bypasses (homoglyphs).
    - Invisible character splitting (token segmentation evasion).
    - Whitespace manipulation / flooding (context window displacement).

    Future Extensions:
    ------------------
    Future releases (Version 2.0+) may add support for:
    - HTML normalization (tag stripping, character reference resolving).
    - Markdown normalization (syntax indicator normalization).
    - Language-aware normalization (script conversions).
    - Plugin-based normalization stages.
    """

    def __init__(self, config: NormalizationConfig | None = None) -> None:
        """
        Initializes the normalizer configuration.

        Args:
            config: A configuration object. Defaults to default NormalizationConfig if None.
        """
        self.config = config or NormalizationConfig()

    def normalize_text(self, text: str) -> NormalizationResult:
        """
        Runs the prompt text through the configured normalization pipeline.

        Args:
            text: The raw user prompt.

        Returns:
            NormalizationResult: The normalized string and trace metadata stats.

        Raises:
            ValidationError: If input is None or not a string.
            NormalizationError: If unrecoverable processing errors occur.
        """
        if text is None:
            raise ValidationError("Input text cannot be None")
        if not isinstance(text, str):
            raise ValidationError("Input text must be a string instance")

        start_time = time.perf_counter()
        
        try:
            current_text = text
            unicode_changes = 0
            invisible_removed = 0
            control_removed = 0
            whitespace_removed = 0

            # 1. Unicode Normalization
            current_text, unicode_changes = self._normalize_unicode(current_text)

            # 2. Invisible Characters Removal
            if self.config.remove_invisible:
                current_text, invisible_removed = self._remove_invisible_chars(current_text)

            # 3. Control Characters Cleanup
            if self.config.remove_control_chars:
                current_text, control_removed = self._cleanup_control_chars(current_text)

            # 4. Whitespace Normalization
            if self.config.normalize_whitespace:
                current_text, whitespace_removed = self._normalize_whitespace(current_text)

            # Calculate processing time
            elapsed_time_ms = self._calculate_elapsed_ms(start_time)
            
            # Aggregate total character removals
            characters_removed = max(0, invisible_removed + control_removed + whitespace_removed)

            metadata = NormalizationMetadata(
                characters_removed=characters_removed,
                unicode_changes=unicode_changes,
                control_characters_removed=control_removed,
                processing_time_ms=elapsed_time_ms
            )

            return NormalizationResult(normalized_text=current_text, metadata=metadata)

        except ValidationError:
            raise
        except Exception as e:
            raise NormalizationError(f"Text normalization pipeline failed: {e}") from e

    def _calculate_elapsed_ms(self, start_time: float) -> float:
        """
        Helper method to calculate pipeline latency.
        """
        return (time.perf_counter() - start_time) * 1000.0

    def _normalize_unicode(self, text: str) -> tuple[str, int]:
        """
        Converts lookalike homoglyphs and composed symbols to canonical forms.
        
        Note: The returned change count is an approximate metric indicating character differences.
        """
        try:
            # pyrefly: ignore [bad-argument-type]
            normalized = unicodedata.normalize(self.config.unicode_form, text)
        except Exception as e:
            raise NormalizationError(f"Unicode normalization failed: {e}") from e
        
        approximate_unicode_changes = 0
        for c1, c2 in zip(text, normalized):
            if c1 != c2:
                approximate_unicode_changes += 1
        approximate_unicode_changes += abs(len(text) - len(normalized))
        return normalized, approximate_unicode_changes

    def _remove_invisible_chars(self, text: str) -> tuple[str, int]:
        """
        Removes zero-width and hidden formatting codes from the text.
        """
        cleaned, count = INVISIBLE_PATTERN.subn("", text)
        return cleaned, count

    def _cleanup_control_chars(self, text: str) -> tuple[str, int]:
        """
        Removes non-printable ASCII control characters.
        """
        cleaned, count = CONTROL_CHAR_PATTERN.subn("", text)
        return cleaned, count

    def _normalize_whitespace(self, text: str) -> tuple[str, int]:
        """
        Collapses sequential whitespace characters and trims string margins.
        """
        if self.config.preserve_newlines:
            # Collapse consecutive horizontal spaces (spaces and tabs)
            text_collapsed, horizontal_changes = HORIZONTAL_WHITESPACE_PATTERN.subn(" ", text)
            
            # Trim horizontal padding on each line
            lines = []
            trim_changes = 0
            for line in text_collapsed.splitlines(keepends=True):
                # Isolate the line endings (\n, \r\n, or \r)
                stripped = line.rstrip("\r\n")
                newlines = line[len(stripped):]
                
                # Trim horizontal spaces
                trimmed_stripped = stripped.strip(" \t")
                trim_changes += len(line) - (len(trimmed_stripped) + len(newlines))
                lines.append(trimmed_stripped + newlines)
                
            cleaned = "".join(lines)
            final_cleaned = cleaned.strip(" \t\r\n")
            trim_changes += len(cleaned) - len(final_cleaned)
            return final_cleaned, horizontal_changes + trim_changes
        else:
            # Collapse all whitespaces to single spaces and trim boundaries
            cleaned, count = WHITESPACE_PATTERN.subn(" ", text)
            final_cleaned = cleaned.strip()
            total_count = count + (len(cleaned) - len(final_cleaned))
            return final_cleaned, total_count
