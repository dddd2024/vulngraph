"""
Taint sanitizers for taint analysis.

Sanitizers are functions that make tainted data safe for specific operations.
"""

from dataclasses import dataclass
from typing import List, Optional
import ast


@dataclass
class Sanitizer:
    """Definition of a sanitizer function."""
    name: str
    description: str
    # What vulnerability types this sanitizer protects against
    protects_against: List[str]
    # Function call patterns that are sanitizers
    call_patterns: List[str]
    # Is this a complete sanitizer or just partial?
    is_complete: bool


# SQL Injection sanitizers
SQL_SANITIZERS = [
    Sanitizer(
        name="parameterized_query",
        description="Using parameterized queries with placeholders",
        protects_against=["SQL Injection"],
        call_patterns=["cursor.execute", "conn.execute"],
        is_complete=True,
    ),
    Sanitizer(
        name="sqlalchemy_text_params",
        description="SQLAlchemy text() with bindparams",
        protects_against=["SQL Injection"],
        call_patterns=["text.bindparams", "text().bindparams"],
        is_complete=True,
    ),
]

# Path Traversal sanitizers
PATH_SANITIZERS = [
    Sanitizer(
        name="path_realpath",
        description="os.path.realpath() resolves and validates path",
        protects_against=["Path Traversal"],
        call_patterns=["os.path.realpath", "os.path.abspath"],
        is_complete=True,
    ),
    Sanitizer(
        name="path_resolve",
        description="pathlib.Path.resolve() resolves and validates path",
        protects_against=["Path Traversal"],
        call_patterns=["Path.resolve", "resolve"],
        is_complete=True,
    ),
    Sanitizer(
        name="secure_filename",
        description="Werkzeug secure_filename removes dangerous characters",
        protects_against=["Path Traversal"],
        call_patterns=["secure_filename"],
        is_complete=True,
    ),
    Sanitizer(
        name="safe_join",
        description="Werkzeug safe_join prevents directory traversal",
        protects_against=["Path Traversal"],
        call_patterns=["safe_join"],
        is_complete=True,
    ),
    Sanitizer(
        name="chroot_jail",
        description="chroot provides filesystem isolation",
        protects_against=["Path Traversal"],
        call_patterns=["os.chroot"],
        is_complete=True,
    ),
]

# Command Injection sanitizers
COMMAND_SANITIZERS = [
    Sanitizer(
        name="shlex_quote",
        description="shlex.quote() escapes shell metacharacters",
        protects_against=["Command Injection"],
        call_patterns=["shlex.quote"],
        is_complete=True,
    ),
    Sanitizer(
        name="list2cmdline",
        description="subprocess.list2cmdline properly escapes arguments",
        protects_against=["Command Injection"],
        call_patterns=["subprocess.list2cmdline"],
        is_complete=True,
    ),
    Sanitizer(
        name="subprocess_no_shell",
        description="Using subprocess with list args and shell=False",
        protects_against=["Command Injection"],
        call_patterns=["subprocess.run", "subprocess.call", "subprocess.Popen"],
        is_complete=True,
    ),
]

# XSS sanitizers
XSS_SANITIZERS = [
    Sanitizer(
        name="html_escape",
        description="HTML escaping prevents XSS",
        protects_against=["XSS"],
        call_patterns=["html.escape", "cgi.escape", "xml.sax.saxutils.escape"],
        is_complete=True,
    ),
    Sanitizer(
        name="bleach_clean",
        description="Bleach library sanitizes HTML",
        protects_against=["XSS"],
        call_patterns=["bleach.clean", "bleach.linkify"],
        is_complete=True,
    ),
    Sanitizer(
        name="jinja_autoescape",
        description="Jinja2 autoescape enabled",
        protects_against=["XSS"],
        call_patterns=["|e", "|escape"],
        is_complete=True,
    ),
]

# SSRF sanitizers
SSRF_SANITIZERS = [
    Sanitizer(
        name="url_whitelist",
        description="URL whitelist validation",
        protects_against=["SSRF"],
        call_patterns=["validators.url", "urlparse"],
        is_complete=False,  # Partial - still need whitelist check
    ),
    Sanitizer(
        name="ip_blacklist",
        description="IP address blacklist (private ranges)",
        protects_against=["SSRF"],
        call_patterns=["ipaddress.ip_address", "socket.getaddrinfo"],
        is_complete=False,
    ),
]

# General input validation
GENERAL_SANITIZERS = [
    Sanitizer(
        name="input_validation",
        description="General input validation (regex, type checking)",
        protects_against=["SQL Injection", "Command Injection", "Path Traversal", "XSS"],
        call_patterns=["re.match", "re.fullmatch", "isinstance", "str.isalnum"],
        is_complete=False,  # Depends on the validation logic
    ),
    Sanitizer(
        name="type_casting",
        description="Type casting to int/float (prevents string injection)",
        protects_against=["SQL Injection", "Command Injection"],
        call_patterns=["int()", "float()"],
        is_complete=False,
    ),
]

# All default sanitizers combined
DEFAULT_SANITIZERS = (
    SQL_SANITIZERS +
    PATH_SANITIZERS +
    COMMAND_SANITIZERS +
    XSS_SANITIZERS +
    SSRF_SANITIZERS +
    GENERAL_SANITIZERS
)


def get_sanitizers_for_vuln_type(vuln_type: str) -> List[Sanitizer]:
    """Get all sanitizers that protect against a specific vulnerability type."""
    return [s for s in DEFAULT_SANITIZERS if vuln_type in s.protects_against]


def is_sanitizer_function(func_name: str) -> Optional[Sanitizer]:
    """Check if a function name matches any sanitizer pattern."""
    for sanitizer in DEFAULT_SANITIZERS:
        for pattern in sanitizer.call_patterns:
            if func_name == pattern or func_name.endswith("." + pattern.split(".")[-1]):
                return sanitizer
    return None


def is_sanitized(node: ast.AST, sanitizer_name: str) -> bool:
    """
    Check if a node is wrapped by a specific sanitizer.
    
    For example, if node is:
        shlex.quote(user_input)
    And sanitizer_name is "shlex_quote", return True.
    """
    # Check if the node is a Call to a sanitizer
    if isinstance(node, ast.Call):
        call_name = _extract_call_name(node)
        if call_name:
            sanitizer = is_sanitizer_function(call_name)
            if sanitizer and sanitizer.name == sanitizer_name:
                return True
    
    # Check if the node is wrapped in a sanitizer call
    # This would require AST parent tracking, which we don't have here
    # The actual implementation should be in the taint engine
    return False


def _extract_call_name(node: ast.Call) -> Optional[str]:
    """Extract the full function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None
