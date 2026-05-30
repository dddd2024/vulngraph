"""
Legacy analyzer adapter for integrating old detection logic.

This adapter provides a bridge between the new audit pipeline and
existing detection modules in the detector/ directory.
TODO: Implement light-weight integration with old detector logic.
"""

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class LegacyAnalyzerAdapter(BaseAnalyzer):
    """
    Adapter for integrating legacy detection logic.
    
    This adapter allows gradual migration of old detection logic
    into the new audit pipeline without breaking existing functionality.
    
    TODO: Implement integration with detector.core.language_router.LanguageRouter
    """
    
    name = "legacy"
    supported_languages = [
        "python", "javascript", "typescript", "java",
        "c", "cpp", "go", "rust", "php"
    ]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """
        Analyze code units using legacy detection logic.
        
        Args:
            code_units: List of code units to analyze
            
        Returns:
            List of RawFinding objects (currently empty)
            
        TODO: Implement integration with old detector modules
        """
        # TODO: Implement integration with old detector logic
        # For now, return empty list as placeholder
        # This allows gradual migration without breaking existing code
        return []
