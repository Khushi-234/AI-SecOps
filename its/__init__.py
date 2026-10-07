"""
ITS (Intelligent Transportation System) — Domain Application Layer.

This package implements the transportation-specific application layer
that integrates with the existing AI-SecOps security middleware framework.

Architecture:
    Raw Dataset
        ↓
    ITS Data Loader / Adapter
        ↓
    Normalized ITS Data Model
        ↓
    ITS Context Builder
        ↓
    AI-SecOps Pipeline (8 stages)
        ↓
    Secure LLM Response
        ↓
    ITS Response + PostgreSQL Audit
"""

from its.application import ITSApplication, build_its_pipeline
from its.integration import AISecOpsAdapter

__version__ = "2.0.0"

__all__ = [
    "ITSApplication",
    "build_its_pipeline",
    "AISecOpsAdapter",
]
