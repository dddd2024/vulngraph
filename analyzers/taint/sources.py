"""
Taint sources for taint analysis.

Sources are points where untrusted data enters the application.
"""

from dataclasses import dataclass
from typing import List, Optional
import ast


@dataclass
class TaintSource:
    """Definition of a taint source."""
    name: str
    description: str
    # Function call patterns that are sources (e.g., ["request.args.get", "input"])
    call_patterns: List[str]
    # Variable name patterns that are sources (e.g., ["request", "params"])
    variable_patterns: List[str]
    # Import patterns (e.g., ["flask.request", "django.http.request"])
    import_patterns: List[str]


# Web framework request sources
WEB_REQUEST_SOURCES = [
    TaintSource(
        name="flask_request_args",
        description="Flask request.args - URL query parameters",
        call_patterns=["request.args.get", "request.args.getlist", "request.args.__getitem__"],
        variable_patterns=["request.args", "request.form", "request.json", "request.data"],
        import_patterns=["flask.request", "from flask import request"],
    ),
    TaintSource(
        name="flask_request_form",
        description="Flask request.form - POST form data",
        call_patterns=["request.form.get", "request.form.getlist"],
        variable_patterns=["request.form"],
        import_patterns=["flask.request"],
    ),
    TaintSource(
        name="flask_request_json",
        description="Flask request.json - JSON body",
        call_patterns=["request.json.get", "request.get_json"],
        variable_patterns=["request.json"],
        import_patterns=["flask.request"],
    ),
    TaintSource(
        name="django_request",
        description="Django request object",
        call_patterns=["request.GET.get", "request.POST.get", "request.FILES.get"],
        variable_patterns=["request.GET", "request.POST", "request.FILES", "request.body"],
        import_patterns=["django.http.request"],
    ),
    TaintSource(
        name="fastapi_request",
        description="FastAPI request/dependency injection",
        call_patterns=["Query", "Path", "Body", "Form", "File", "Header", "Cookie"],
        variable_patterns=["request", "params", "query_params"],
        import_patterns=["fastapi", "starlette.requests"],
    ),
    TaintSource(
        name="bottle_request",
        description="Bottle request object",
        call_patterns=["request.query.get", "request.forms.get", "request.json"],
        variable_patterns=["request.query", "request.forms", "request.json"],
        import_patterns=["bottle.request"],
    ),
]

# User input sources
USER_INPUT_SOURCES = [
    TaintSource(
        name="builtin_input",
        description="Python builtin input() function",
        call_patterns=["input"],
        variable_patterns=[],
        import_patterns=[],
    ),
    TaintSource(
        name="sys_argv",
        description="Command line arguments",
        call_patterns=[],
        variable_patterns=["sys.argv"],
        import_patterns=["sys"],
    ),
    TaintSource(
        name="os_environ",
        description="Environment variables",
        call_patterns=["os.environ.get", "os.getenv"],
        variable_patterns=["os.environ"],
        import_patterns=["os"],
    ),
]

# File/network sources
IO_SOURCES = [
    TaintSource(
        name="file_read",
        description="File read operations",
        call_patterns=["open", "read", "readline", "readlines"],
        variable_patterns=[],
        import_patterns=[],
    ),
    TaintSource(
        name="socket_recv",
        description="Socket receive operations",
        call_patterns=["socket.recv", "recvfrom", "recv_into"],
        variable_patterns=[],
        import_patterns=["socket"],
    ),
    TaintSource(
        name="urllib_request",
        description="URL request data",
        call_patterns=["urllib.request.urlopen", "urlopen"],
        variable_patterns=[],
        import_patterns=["urllib.request"],
    ),
]

# Database sources (data from DB can also be tainted)
DB_SOURCES = [
    TaintSource(
        name="db_query_result",
        description="Database query results",
        call_patterns=["cursor.fetchone", "cursor.fetchall", "cursor.fetchmany"],
        variable_patterns=[],
        import_patterns=["sqlite3", "mysql.connector", "psycopg2"],
    ),
]

# All default sources combined
DEFAULT_SOURCES = WEB_REQUEST_SOURCES + USER_INPUT_SOURCES + IO_SOURCES + DB_SOURCES


def get_source_by_name(name: str) -> Optional[TaintSource]:
    """Get a taint source by its name."""
    for source in DEFAULT_SOURCES:
        if source.name == name:
            return source
    return None


def is_tainted_variable(var_name: str, tracked_vars: set) -> bool:
    """Check if a variable name is in the tracked tainted variables set."""
    # Direct match
    if var_name in tracked_vars:
        return True
    
    # Check if it's an attribute access of a tainted object
    # e.g., if "request" is tainted, "request.args" should also be considered
    for tracked in tracked_vars:
        if var_name.startswith(tracked + ".") or var_name.startswith(tracked + "["):
            return True
    
    return False


def extract_variable_name(node: ast.AST) -> Optional[str]:
    """Extract the full variable name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        value = extract_variable_name(node.value)
        if value:
            return f"{value}.{node.attr}"
        return node.attr
    elif isinstance(node, ast.Subscript):
        value = extract_variable_name(node.value)
        if value:
            return f"{value}[...]"
        return "[...]"
    return None
