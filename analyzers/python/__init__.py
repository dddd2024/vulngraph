"""
Python analyzer package — migrates detector capabilities into the analyzers architecture.

Provides a unified PythonAnalyzer (BaseAnalyzer) that internally delegates to
the detector's AST, Regex, and Taint engines, producing RawFinding objects
compatible with the audit pipeline.
"""

from analyzers.python.python_analyzer import PythonAnalyzer

__all__ = ["PythonAnalyzer"]
