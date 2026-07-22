# logger.py
"""Central logging configuration for validation activities.

Provides a standardized logger instance for recording validation executions,
warnings, failures, and debug traces across all validators.
"""

import logging
import sys


def setup_validator_logger(
    name: str = "input_validator",
    level: int = logging.INFO
) -> logging.Logger:
    """Configures and returns a thread-safe central logger for input validation.

    Args:
        name: Logger module hierarchy identifier.
        level: Minimum logging level.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding multiple handlers on module re-imports
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger.propagate = False
    return logger


# Global logger instance used across the module
validator_logger = setup_validator_logger()