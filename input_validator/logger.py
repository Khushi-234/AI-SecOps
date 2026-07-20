# logger.py
"""Central logger for the Input Validator module.

Configures a module‑level logger that can be imported by any validator
or component. The logger is deliberately lightweight – it uses ``INFO``
as the default level and outputs a timestamp, logger name and message.
"""

import logging

# Create a logger for this package
validator_logger = logging.getLogger("input_validator")
validator_logger.setLevel(logging.INFO)

# Ensure we have at least one handler (avoid duplicate handlers)
if not validator_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    validator_logger.addHandler(handler)
