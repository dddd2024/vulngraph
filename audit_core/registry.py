"""
Analyzer registry for managing and discovering analyzers.

The registry provides a central place to register analyzers
and retrieve them for use in the audit pipeline.
"""

from typing import Optional
from analyzers.base import BaseAnalyzer
from analyzers.pattern_analyzer import PatternAnalyzer
from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.taint.taint_engine import TaintAnalyzer
from analyzers.legacy_adapter import LegacyAnalyzerAdapter
from analyzers.python.python_analyzer import PythonAnalyzer
from analyzers.javascript.js_pattern_analyzer import JSPatternAnalyzer
from analyzers.java.java_pattern_analyzer import JavaPatternAnalyzer
from analyzers.c_cpp.c_pattern_analyzer import CPatternAnalyzer


class AnalyzerRegistry:
    """
    Registry for managing analyzers.
    
    Analyzers can be registered and retrieved by name or language support.
    """
    
    def __init__(self):
        self._analyzers: dict[str, BaseAnalyzer] = {}
    
    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Register an analyzer.
        
        Args:
            analyzer: The analyzer instance to register
        """
        self._analyzers[analyzer.name] = analyzer
    
    def get(self, name: str) -> Optional[BaseAnalyzer]:
        """
        Get an analyzer by name.
        
        Args:
            name: The name of the analyzer
            
        Returns:
            The analyzer instance or None if not found
        """
        return self._analyzers.get(name)
    
    def get_analyzers(self) -> list[BaseAnalyzer]:
        """
        Get all registered analyzers.
        
        Returns:
            List of all registered analyzer instances
        """
        return list(self._analyzers.values())
    
    def get_analyzers_for_language(self, language: str) -> list[BaseAnalyzer]:
        """
        Get analyzers that support a specific language.
        
        Args:
            language: The programming language to check
            
        Returns:
            List of analyzers supporting the language
        """
        return [
            analyzer for analyzer in self._analyzers.values()
            if language.lower() in [lang.lower() for lang in analyzer.supported_languages]
        ]
    
    def unregister(self, name: str) -> None:
        """
        Unregister an analyzer.
        
        Args:
            name: The name of the analyzer to unregister
        """
        if name in self._analyzers:
            del self._analyzers[name]
    
    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()


def build_default_registry(*, enable_legacy: bool = False) -> AnalyzerRegistry:
    """
    Build a registry with default analyzers.
    
    The ``PythonAnalyzer`` (name="python") is the primary Python analyzer.
    The ``LegacyAnalyzerAdapter`` (name="legacy") is **not** registered by
    default; pass ``enable_legacy=True`` to include it as a fallback.

    Parameters
    ----------
    enable_legacy:
        If ``True``, also register ``LegacyAnalyzerAdapter``.  Defaults to
        ``False`` — new code should not depend on the legacy path.

    Returns:
        Registry with python, pattern, AST, taint, and language-specific
        analyzers registered.  Legacy adapter is only included when
        ``enable_legacy=True``.
    """
    registry = AnalyzerRegistry()
    # New Python analyzer (preferred — wraps AST/Regex/Taint engines)
    registry.register(PythonAnalyzer())
    # Core analyzers (Python-focused)
    registry.register(PatternAnalyzer())
    registry.register(ASTAnalyzer())
    registry.register(TaintAnalyzer())
    # Legacy fallback (only when explicitly requested)
    if enable_legacy:
        registry.register(LegacyAnalyzerAdapter())
    # Language-specific analyzers
    registry.register(JSPatternAnalyzer())
    registry.register(JavaPatternAnalyzer())
    registry.register(CPatternAnalyzer())
    return registry
