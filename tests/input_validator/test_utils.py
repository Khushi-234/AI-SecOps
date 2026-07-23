# test_utils.py
"""Unit tests for utility functions in input_validator."""

import pytest
from input_validator.utils import (
    parse_raw_payload,
    normalize_unicode_text,
    count_utf8_bytes,
    extract_file_extension,
    truncate_text,
    is_empty,
    within_length,
    is_valid_utf8,
    matches_regex,
)
from input_validator.models import ConversationPayload


class TestUtils:
    """Test suite for shared utility functions in input_validator.utils."""

    def test_parse_raw_payload_dict(self) -> None:
        raw_dict = {
            "user": "What is AI?",
            "history": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi!"},
            ],
        }
        payload = parse_raw_payload(raw_dict)
        assert isinstance(payload, ConversationPayload)
        assert payload.user == "What is AI?"
        assert len(payload.history) == 2
        assert payload.history[0].role == "user"
        assert payload.history[1].content == "Hi!"

    def test_parse_raw_payload_json_str(self) -> None:
        json_str = '{"user": "Explain quantum computing", "history": []}'
        payload = parse_raw_payload(json_str)
        assert isinstance(payload, ConversationPayload)
        assert payload.user == "Explain quantum computing"
        assert payload.history == []

    def test_parse_raw_payload_invalid_inputs(self) -> None:
        assert parse_raw_payload("invalid json {") is None
        assert parse_raw_payload([1, 2, 3]) is None
        assert parse_raw_payload({"user": 1234}) is None
        assert parse_raw_payload({"user": "Hi", "history": "not a list"}) is None

    def test_parse_raw_payload_malformed_history_item(self) -> None:
        raw_dict = {
            "user": "Test prompt",
            "history": ["string_history_item", {"role": "system", "content": "Init"}],
        }
        payload = parse_raw_payload(raw_dict)
        assert payload is not None
        assert len(payload.history) == 2
        assert payload.history[0].role == "invalid_structure"
        assert payload.history[0].content == "string_history_item"

    def test_normalize_unicode_text(self) -> None:
        assert normalize_unicode_text("") == ""
        assert normalize_unicode_text("Hello World") == "Hello World"
        # Half-width katakana normalization in NFKC
        half_width = "ｶ"
        assert normalize_unicode_text(half_width, "NFKC") == "カ"

    def test_count_utf8_bytes(self) -> None:
        assert count_utf8_bytes("") == 0
        assert count_utf8_bytes("abc") == 3
        assert count_utf8_bytes("🚀") == 4  # Emoji is 4 bytes in UTF-8
        assert count_utf8_bytes("Café") == 5

    def test_extract_file_extension(self) -> None:
        assert extract_file_extension("") == ""
        assert extract_file_extension("document.pdf") == "pdf"
        assert extract_file_extension("IMAGE.PNG") == "png"
        assert extract_file_extension("archive.tar.gz") == "gz"
        assert extract_file_extension(".env") == ""
        assert extract_file_extension("no_ext_file") == ""

    def test_truncate_text(self) -> None:
        assert truncate_text("") == ""
        assert truncate_text("Short text", max_length=20) == "Short text"
        assert (
            truncate_text("Long text that needs truncation", max_length=10)
            == "Long text ..."
        )
        assert truncate_text("Long text", max_length=4, suffix="--") == "Long--"

    def test_is_empty(self) -> None:
        assert is_empty(None) is True
        assert is_empty("") is True
        assert is_empty(b"") is True
        assert is_empty([]) is True
        assert is_empty({}) is True
        assert is_empty(set()) is True
        assert is_empty(()) is True

        assert is_empty("text") is False
        assert is_empty([1]) is False
        assert is_empty({"a": 1}) is False
        assert is_empty(0) is False
        assert is_empty(False) is False

    def test_within_length(self) -> None:
        assert within_length("hello", min_len=1, max_len=10) is True
        assert within_length("hello", min_len=6, max_len=10) is False
        assert within_length("hello", min_len=1, max_len=4) is False

    def test_is_valid_utf8(self) -> None:
        assert is_valid_utf8(b"Hello world") is True
        assert is_valid_utf8(b"\x80\x81\xfe\xff") is False

    def test_matches_regex(self) -> None:
        pattern = r"^\d{3}-\d{2}-\d{4}$"
        assert matches_regex(pattern, "123-45-6789") is True
        assert matches_regex(pattern, "123456789") is False
