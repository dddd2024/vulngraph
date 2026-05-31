"""
Python analyzers registration.

Registers all Python-language analyzers (PythonAnalyzer, PatternAnalyzer, ASTAnalyzer)
into the provided AnalyzerRegistry.
"""

from __future__ import annotations

from audit_core.registry import AnalyzerRegistry


def register_analyzers(registry: AnalyzerRegistry) -> None:
    """
    Register Python-language analyzers into the given registry.

    Args:
        registry: The AnalyzerRegistry instance to register analyzers into.
    """
    from analyzers.python.python_analyzer import PythonAnalyzer
    from analyzers.pattern_analyzer import PatternAnalyzer
    from analyzers.ast_analyzer import ASTAnalyzer

    registry.register(PythonAnalyzer())
    registry.register(PatternAnalyzer())
    registry.register(ASTAnalyzer())
