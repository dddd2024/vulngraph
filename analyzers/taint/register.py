"""
Taint analysis registration.

Registers the TaintAnalyzer into the provided AnalyzerRegistry.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register taint analysis analyzers into the given registry.

    Args:
        registry: The AnalyzerRegistry instance to register analyzers into.
    """
    from analyzers.taint.taint_engine import TaintAnalyzer

    registry.register(TaintAnalyzer())
