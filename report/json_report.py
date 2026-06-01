"""
JSON report generator.

Generates JSON-format audit reports from AuditResult objects.
"""

from audit_core.models import AuditResult


def build_json_report(result: AuditResult) -> dict:
    """
    Build a JSON-serializable report from an audit result.
    
    Args:
        result: The audit result to convert
        
    Returns:
        Dictionary that can be serialized to JSON
    """
    return result.to_dict()
