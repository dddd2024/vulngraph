"""
CWE mapper for vulnerability type classification.

Maps vulnerability types to CWE (Common Weakness Enumeration) identifiers.
Supports case-insensitive matching and snake_case type names.
"""

from typing import Any

# CWE mapping for common vulnerability types
# Keys are normalized to lowercase for case-insensitive lookup
CWE_MAPPING = {
    # SQL Injection
    "sql injection": {"id": "CWE-89", "name": "SQL Injection", "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    "sql_injection": {"id": "CWE-89", "name": "SQL Injection", "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"},
    
    # Path Traversal
    "path traversal": {"id": "CWE-22", "name": "Path Traversal", "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    "path_traversal": {"id": "CWE-22", "name": "Path Traversal", "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"},
    
    # Command Injection
    "command injection": {"id": "CWE-78", "name": "OS Command Injection", "description": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    "command_injection": {"id": "CWE-78", "name": "OS Command Injection", "description": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"},
    
    # XSS
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "cross-site scripting (xss)": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    "cross site scripting": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)", "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"},
    
    # SSRF
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL"},
    "server-side request forgery (ssrf)": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL"},
    "server side request forgery": {"id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL"},
    
    # Hardcoded Secret
    "hardcoded secret": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    "hardcoded_secret": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    "hardcoded credentials": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    "hardcoded_credentials": {"id": "CWE-798", "name": "Use of Hard-coded Credentials", "description": "The software contains hard-coded credentials, such as a password or cryptographic key"},
    
    # Weak Cryptography
    "weak cryptography": {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information"},
    "weak_crypto": {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information"},
    "weak crypto": {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information"},
    
    # Insecure Deserialization
    "insecure deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "insecure_deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "unsafe deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    "unsafe_deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data", "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
    
    # Additional mappings for existing types
    "privilege escalation": {"id": "CWE-269", "name": "Improper Privilege Management", "description": "The software does not properly assign, modify, track, or check privileges for an actor"},
    "dangerous code execution": {"id": "CWE-95", "name": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", "description": "The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input"},
    "debug mode enabled": {"id": "CWE-489", "name": "Active Debug Code", "description": "The application is deployed with active debug code that can create unintended entry points or expose sensitive information"},
    "insecure tls verification": {"id": "CWE-295", "name": "Improper Certificate Validation", "description": "The software does not validate, or incorrectly validates, a certificate"},
    "buffer overflow": {"id": "CWE-120", "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer"},
    "format string vulnerability": {"id": "CWE-134", "name": "Use of Externally-Controlled Format String", "description": "The software uses a function that accepts a format string as an argument, but the format string originates from an external source"},
    "integer overflow": {"id": "CWE-190", "name": "Integer Overflow or Wraparound", "description": "The software performs a calculation that can produce an integer overflow or wraparound"},
    "null pointer dereference": {"id": "CWE-476", "name": "NULL Pointer Dereference", "description": "The software dereferences a pointer that it expects to be valid but is NULL"},
    "file upload": {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type", "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment"},
    "insecure random": {"id": "CWE-338", "name": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)", "description": "The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG's algorithm is not cryptographically strong"},
    "info disclosure": {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor", "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information"},
    "debug info": {"id": "CWE-489", "name": "Active Debug Code", "description": "The application is deployed with active debug code that can create unintended entry points or expose sensitive information"},
}


def _normalize_type(vulnerability_type: str) -> str:
    """
    Normalize vulnerability type for lookup.
    
    Converts to lowercase and handles various formats.
    
    Args:
        vulnerability_type: The vulnerability type string
        
    Returns:
        Normalized type string
    """
    if not vulnerability_type:
        return ""
    return vulnerability_type.lower().strip()


def map_cwe(vulnerability_type: str) -> dict[str, Any]:
    """
    Map a vulnerability type to CWE information.
    
    Supports:
    - Case-insensitive matching
    - snake_case type names
    - Common aliases
    
    Args:
        vulnerability_type: The vulnerability type string (e.g., "sql_injection", "SQL Injection")
        
    Returns:
        Dictionary with CWE information:
        - id: CWE identifier (e.g., "CWE-89")
        - name: CWE name
        - description: Short description
        
        Returns a default "CWE-UNKNOWN" entry if the type is not recognized.
    """
    if not vulnerability_type:
        return {
            "id": "CWE-UNKNOWN",
            "name": "Unknown",
            "description": "Unknown or unclassified vulnerability type"
        }
    
    # Normalize the input
    normalized = _normalize_type(vulnerability_type)
    
    # Try direct lookup
    if normalized in CWE_MAPPING:
        return CWE_MAPPING[normalized]
    
    # Try with underscores replaced by spaces
    with_spaces = normalized.replace("_", " ")
    if with_spaces in CWE_MAPPING:
        return CWE_MAPPING[with_spaces]
    
    # Try with spaces replaced by underscores
    with_underscores = normalized.replace(" ", "_")
    if with_underscores in CWE_MAPPING:
        return CWE_MAPPING[with_underscores]
    
    # Return default for unknown types
    return {
        "id": "CWE-UNKNOWN",
        "name": vulnerability_type,
        "description": "Unknown or unclassified vulnerability type"
    }


def get_cwe_id(vulnerability_type: str) -> str:
    """
    Get CWE ID for a vulnerability type.
    
    Args:
        vulnerability_type: The vulnerability type string
        
    Returns:
        CWE identifier (e.g., "CWE-89") or "CWE-UNKNOWN"
    """
    mapping = map_cwe(vulnerability_type)
    return mapping["id"]


def get_all_cwe_mappings() -> dict[str, dict[str, Any]]:
    """
    Get all CWE mappings.
    
    Returns:
        Dictionary of all CWE mappings (normalized keys)
    """
    return CWE_MAPPING.copy()


def is_known_vulnerability_type(vulnerability_type: str) -> bool:
    """
    Check if a vulnerability type is known.
    
    Args:
        vulnerability_type: The vulnerability type string
        
    Returns:
        True if the type is known, False otherwise
    """
    if not vulnerability_type:
        return False
    
    normalized = _normalize_type(vulnerability_type)
    
    # Check various forms
    if normalized in CWE_MAPPING:
        return True
    if normalized.replace("_", " ") in CWE_MAPPING:
        return True
    if normalized.replace(" ", "_") in CWE_MAPPING:
        return True
    
    return False