"""
Firewall Logger Module

Handles logging for detector execution, detections (alarms), errors, and audit trails.
"""

import logging

logger = logging.getLogger("prompt_firewall")


class FirewallLogger:
    """
    Log manager for the Prompt Firewall.
    """

    @staticmethod
    def log_detection(
        detector_name: str, threat_type: str, severity: str, confidence: float
    ) -> None:
        """
        Logs a security threat detection event.
        """
        logger.warning(
            f"[THREAT DETECTED] Detector: {detector_name} | Type: {threat_type} | Severity: {severity} | Confidence: {confidence:.2f}"
        )

    @staticmethod
    def log_error(detector_name: str, error_message: str) -> None:
        """
        Logs an execution error in a detector.
        """
        logger.error(
            f"[DETECTOR ERROR] Detector: {detector_name} | Error: {error_message}"
        )
