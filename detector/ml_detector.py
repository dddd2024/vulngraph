"""
ML-Enhanced Vulnerability Detector
Wraps existing rule-based detection with ML-based detection capabilities
"""
from pathlib import Path
from typing import List, Dict, Any, Optional

from .vuln_detector import (
    detect_sql_injection,
    detect_path_traversal,
    detect_privilege_escalation,
    detect_all as rule_detect_all,
)

# Lazy import to avoid circular dependency
_ml_inference = None


def _get_ml_inference():
    """Lazy load ML inference to avoid import errors if dependencies not installed"""
    global _ml_inference
    if _ml_inference is None:
        try:
            from deeplearning.inference import get_ml_inference
            _ml_inference = get_ml_inference()
        except ImportError:
            return None
    return _ml_inference


def detect_with_ml(file_path: str) -> List[Dict[str, Any]]:
    """
    Detect vulnerabilities using ML-based detection.
    This complements the rule-based detection with ML capabilities.
    
    Args:
        file_path: Path to the Python file to analyze
    
    Returns:
        List of vulnerability findings from ML detection
    """
    ml_inf = _get_ml_inference()
    if ml_inf is None:
        return []
    
    try:
        code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        # Get rule-based findings to avoid duplicates
        rule_findings = []
        rule_findings.extend(detect_sql_injection(file_path))
        rule_findings.extend(detect_path_traversal(file_path))
        rule_findings.extend(detect_privilege_escalation(file_path))
        
        # Run ML detection
        ml_findings = ml_inf.detect_vulnerabilities(
            code=code,
            filename=file_path,
            existing_findings=rule_findings
        )
        
        return ml_findings
        
    except Exception as e:
        # Silently return empty on error to maintain backward compatibility
        return []


def is_ml_available() -> bool:
    """Check if ML detection is available"""
    ml_inf = _get_ml_inference()
    return ml_inf is not None


def is_real_ml_model_loaded() -> bool:
    """Check if actual ML model is loaded (not just fallback)"""
    ml_inf = _get_ml_inference()
    if ml_inf is None:
        return False
    return ml_inf.is_ml_available()


def get_ml_status() -> Dict[str, Any]:
    """Get ML detection status information"""
    ml_inf = _get_ml_inference()
    
    if ml_inf is None:
        return {
            "available": False,
            "model_loaded": False,
            "status": "not_installed",
            "message": "ML dependencies not installed"
        }
    
    real_model = ml_inf.is_ml_available()
    
    return {
        "available": True,
        "model_loaded": real_model,
        "status": "ready" if real_model else "fallback",
        "message": "ML model loaded" if real_model else "Using pattern-based fallback"
    }


def enhanced_detect_all(repo_root: str = "repo") -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Enhanced detection that combines rule-based and ML-based detection.
    
    Args:
        repo_root: Root directory of the repository to scan
    
    Returns:
        Tuple of (findings list, ml status dict)
    """
    findings: List[Dict[str, Any]] = []
    
    # Get rule-based findings
    rule_findings = rule_detect_all(repo_root)
    findings.extend(rule_findings)
    
    # Add ML engine tag to rule findings
    for f in findings:
        if "engine" in f and f["engine"] == "ast":
            f["engines"] = ["ast"]
    
    # Get ML status
    ml_status = get_ml_status()
    
    # Add ML findings if available
    ml_inf = _get_ml_inference()
    if ml_inf is not None:
        from parser.repo_scanner import scan_repo
        
        for file_path in scan_repo(repo_root, exts=(".py",)):
            ml_findings = detect_with_ml(file_path)
            for ml_f in ml_findings:
                # Ensure proper engine tag
                ml_f["engine"] = "ml"
                if "engines" not in ml_f:
                    ml_f["engines"] = ["ml"]
                findings.append(ml_f)
    
    return findings, ml_status
