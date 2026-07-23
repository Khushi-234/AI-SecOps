# test_logger.py
"""Unit tests for Central Logger setup in input_validator."""

import logging
from input_validator.logger import setup_validator_logger, validator_logger


class TestValidatorLogger:
    """Test suite for setup_validator_logger and central logger configuration."""

    def test_global_validator_logger_instance(self) -> None:
        assert isinstance(validator_logger, logging.Logger)
        assert validator_logger.name == "input_validator"
        assert validator_logger.level == logging.INFO
        assert len(validator_logger.handlers) >= 1
        assert validator_logger.propagate is False

    def test_setup_validator_logger_custom_name_and_level(self) -> None:
        logger_name = "test_custom_validator"
        logger = setup_validator_logger(name=logger_name, level=logging.DEBUG)
        assert logger.name == logger_name
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert logger.propagate is False

    def test_setup_validator_logger_no_duplicate_handlers(self) -> None:
        logger_name = "test_dedup_logger"
        logger1 = setup_validator_logger(name=logger_name, level=logging.INFO)
        initial_handlers_count = len(logger1.handlers)
        logger2 = setup_validator_logger(name=logger_name, level=logging.INFO)
        assert len(logger2.handlers) == initial_handlers_count

    def test_logger_formatter_structure(self) -> None:
        logger = setup_validator_logger("test_formatter_logger")
        handler = logger.handlers[0]
        assert handler.formatter is not None
        fmt = handler.formatter._fmt
        assert fmt is not None
        assert "%(asctime)s" in fmt
        assert "%(levelname)s" in fmt
        assert "%(name)s" in fmt
        assert "%(message)s" in fmt
