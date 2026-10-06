"""
ITS Context Construction Package.

Responsible for assembling domain-specific transportation context
from ITS data sources and user queries. Does NOT perform any
security analysis, risk scoring, or policy decisions.
"""

from its.context.context_builder import ITSContextBuilder

__all__ = ["ITSContextBuilder"]
