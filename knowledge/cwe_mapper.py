"""
CWE mapper for vulnerability type classification.

Maps vulnerability types to CWE (Common Weakness Enumeration) identifiers.
"""

# CWE mapping for common vulnerability types
CWE_MAPPING = {
    "SQL Injection": {"id": "CWE-89", "name": "SQL Injection", "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    "Path Traversal": {"id": "CWE-22", "name": "Path Traversal", "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    "Privilege Escalation": {"id": "CWE-269", "name": "Improper Privilege Management", "description": "The software does not properly assign, modify, track, or check privileges for an actor"},
    "Command Injection": {"id": "CWE-78", "name": "OS Command Injection", "description": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    "Unsafe Deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "Insecure Deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "Hardcoded Secret": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    "Hardcoded Credentials": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    "Cross-Site Scripting (XSS)": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "XSS": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "SSRF": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL"},
    "Dangerous Code Execution": {"id": "CWE-95", "name": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", "description": "The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input"},
    "Weak Cryptography": {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information"},
    "Debug Mode Enabled": {"id": "CWE-489", "name": "Active Debug Code", "description": "The application is deployed with active debug code that can create unintended entry points or expose sensitive information"},
    "Insecure TLS Verification": {"id": "CWE-295", "name": "Improper Certificate Validation", "description": "The software does not validate, or incorrectly validates, a certificate"},
    "Buffer Overflow": {"id": "CWE-120", "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer"},
    "Format String Vulnerability": {"id": "CWE-134", "name": "Use of Externally-Controlled Format String", "description": "The software uses a function that accepts a format string as an argument, but the format string originates from an external source"},
    "Integer Overflow": {"id": "CWE-190", "name": "Integer Overflow or Wraparound", "description": "The software performs a calculation that can produce an integer overflow or wraparound"},
    "Null Pointer Dereference": {"id": "CWE-476", "name": "NULL Pointer Dereference", "description": "The software dereferences a pointer that it expects to be valid but is NULL"},
}


def map_cwe(vulnerability_type: str) -> dict:
    """
    Map a vulnerability type to CWE information.
    
    Args:
        vulnerability_type: The vulnerability type string
        
    Returns:
        Dictionary with CWE information:
        - id: CWE identifier (e.g., "CWE-89")
        - name: CWE name
        - description: Short description
        
        Returns a default "Unknown" entry if the type is not recognized.
    """
    if vulnerability_type in CWE_MAPPING:
        return CWE_MAPPING[vulnerability_type]
    
    # Return default for unknown types
    return {
        "id": "CWE-UNKNOWN",
        "name": vulnerability_type,
        "description": "Unknown or unclassified vulnerability type"
    }
