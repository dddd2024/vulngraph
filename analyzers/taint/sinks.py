"""
Taint sinks for taint analysis.

Sinks are points where tainted data can cause security vulnerabilities.
"""

from dataclasses import dataclass
from typing import List, Optional
import ast


@dataclass
class TaintSink:
    """Definition of a taint sink."""
    name: str
    description: str
    # Vulnerability type
    vuln_type: str
    # Severity: ERROR, WARN, INFO
    severity: str
    # Function call patterns that are sinks
    call_patterns: List[str]
    # Argument positions that are vulnerable (0-indexed, None means all)
    vulnerable_args: List[Optional[int]]
    # Sanitizer functions that can make data safe
    sanitizer_patterns: List[str]


# SQL Injection sinks
SQL_INJECTION_SINKS = [
    TaintSink(
        name="sqlite3_execute",
        description="SQLite3 cursor.execute() with string query",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["cursor.execute", "conn.execute", "connection.execute"],
        vulnerable_args=[0],  # First argument (query string)
        sanitizer_patterns=["sqlite3.paramstyle", "parameterized_query"],
    ),
    TaintSink(
        name="sqlite3_executemany",
        description="SQLite3 cursor.executemany() with string query",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["cursor.executemany", "conn.executemany"],
        vulnerable_args=[0],
        sanitizer_patterns=["sqlite3.paramstyle"],
    ),
    TaintSink(
        name="sqlite3_executescript",
        description="SQLite3 cursor.executescript() - dangerous multi-statement",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["cursor.executescript", "conn.executescript"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
    TaintSink(
        name="mysql_cursor_execute",
        description="MySQL cursor.execute() with string query",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["cursor.execute"],
        vulnerable_args=[0],
        sanitizer_patterns=["%s", "?"],
    ),
    TaintSink(
        name="psycopg2_execute",
        description="PostgreSQL psycopg2 cursor.execute()",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["cursor.execute"],
        vulnerable_args=[0],
        sanitizer_patterns=["%s"],
    ),
    TaintSink(
        name="sqlalchemy_raw",
        description="SQLAlchemy raw SQL execution",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["session.execute", "db.session.execute", "engine.execute"],
        vulnerable_args=[0],
        sanitizer_patterns=["text()", "literal_column()"],
    ),
    TaintSink(
        name="sqlalchemy_text",
        description="SQLAlchemy text() with f-string",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["text"],
        vulnerable_args=[0],
        sanitizer_patterns=["bindparams"],
    ),
    TaintSink(
        name="django_raw_sql",
        description="Django raw SQL execution",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["Model.objects.raw", "cursor.execute"],
        vulnerable_args=[0],
        sanitizer_patterns=["%s"],
    ),
    TaintSink(
        name="pandas_read_sql",
        description="Pandas read_sql with query string",
        vuln_type="SQL Injection",
        severity="ERROR",
        call_patterns=["pd.read_sql", "pandas.read_sql"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
]

# Path Traversal sinks
PATH_TRAVERSAL_SINKS = [
    TaintSink(
        name="open_file",
        description="Python builtin open() for file access",
        vuln_type="Path Traversal",
        severity="ERROR",
        call_patterns=["open"],
        vulnerable_args=[0],
        sanitizer_patterns=["os.path.abspath", "os.path.realpath", "pathlib.Path.resolve"],
    ),
    TaintSink(
        name="os_path_join",
        description="os.path.join with untrusted component",
        vuln_type="Path Traversal",
        severity="WARN",
        call_patterns=["os.path.join"],
        vulnerable_args=[1, 2],  # Second and subsequent components
        sanitizer_patterns=["os.path.normpath", "os.path.realpath"],
    ),
    TaintSink(
        name="pathlib_path",
        description="pathlib.Path with untrusted path",
        vuln_type="Path Traversal",
        severity="WARN",
        call_patterns=["Path", "Path.__truediv__", "Path.joinpath"],
        vulnerable_args=[0, 1],
        sanitizer_patterns=["Path.resolve"],
    ),
    TaintSink(
        name="shutil_operations",
        description="shutil file operations",
        vuln_type="Path Traversal",
        severity="ERROR",
        call_patterns=["shutil.copy", "shutil.move", "shutil.copy2", "shutil.copyfile"],
        vulnerable_args=[0, 1],
        sanitizer_patterns=["os.path.realpath"],
    ),
    TaintSink(
        name="send_file",
        description="Flask send_file with user-controlled path",
        vuln_type="Path Traversal",
        severity="ERROR",
        call_patterns=["send_file"],
        vulnerable_args=[0],
        sanitizer_patterns=["safe_join", "secure_filename"],
    ),
    TaintSink(
        name="django_serve",
        description="Django file serving",
        vuln_type="Path Traversal",
        severity="ERROR",
        call_patterns=["serve", "FileResponse"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
]

# Command Injection sinks
COMMAND_INJECTION_SINKS = [
    TaintSink(
        name="os_system",
        description="os.system() shell execution",
        vuln_type="Command Injection",
        severity="ERROR",
        call_patterns=["os.system"],
        vulnerable_args=[0],
        sanitizer_patterns=["shlex.quote", "subprocess.list2cmdline"],
    ),
    TaintSink(
        name="os_popen",
        description="os.popen() shell execution",
        vuln_type="Command Injection",
        severity="ERROR",
        call_patterns=["os.popen", "os.popen2", "os.popen3"],
        vulnerable_args=[0],
        sanitizer_patterns=["shlex.quote"],
    ),
    TaintSink(
        name="subprocess_shell",
        description="subprocess with shell=True",
        vuln_type="Command Injection",
        severity="ERROR",
        call_patterns=["subprocess.run", "subprocess.call", "subprocess.Popen"],
        vulnerable_args=[0],
        sanitizer_patterns=["shlex.quote"],
    ),
    TaintSink(
        name="eval_exec",
        description="eval() and exec() code execution",
        vuln_type="Code Injection",
        severity="ERROR",
        call_patterns=["eval", "exec"],
        vulnerable_args=[0],
        sanitizer_patterns=["ast.literal_eval"],
    ),
    TaintSink(
        name="compile_code",
        description="compile() with untrusted source",
        vuln_type="Code Injection",
        severity="ERROR",
        call_patterns=["compile"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
    TaintSink(
        name="pickle_load",
        description="pickle deserialization",
        vuln_type="Insecure Deserialization",
        severity="ERROR",
        call_patterns=["pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
    TaintSink(
        name="yaml_load",
        description="YAML unsafe load",
        vuln_type="Insecure Deserialization",
        severity="ERROR",
        call_patterns=["yaml.load", "yaml.unsafe_load"],
        vulnerable_args=[0],
        sanitizer_patterns=["yaml.safe_load"],
    ),
]

# SSRF sinks
SSRF_SINKS = [
    TaintSink(
        name="requests_get",
        description="requests.get() with user-controlled URL",
        vuln_type="SSRF",
        severity="ERROR",
        call_patterns=["requests.get", "requests.post", "requests.put", "requests.delete"],
        vulnerable_args=[0],
        sanitizer_patterns=["urljoin", "urlparse", "validators.url"],
    ),
    TaintSink(
        name="urllib_open",
        description="urllib.request.urlopen with user-controlled URL",
        vuln_type="SSRF",
        severity="ERROR",
        call_patterns=["urllib.request.urlopen", "urlopen"],
        vulnerable_args=[0],
        sanitizer_patterns=["urlparse"],
    ),
    TaintSink(
        name="http_client",
        description="http.client request with user-controlled host",
        vuln_type="SSRF",
        severity="ERROR",
        call_patterns=["http.client.HTTPConnection", "http.client.HTTPSConnection"],
        vulnerable_args=[0],
        sanitizer_patterns=[],
    ),
]

# XSS sinks (for web frameworks)
XSS_SINKS = [
    TaintSink(
        name="flask_render_template_string",
        description="Flask render_template_string with user input",
        vuln_type="XSS",
        severity="ERROR",
        call_patterns=["render_template_string"],
        vulnerable_args=[0],
        sanitizer_patterns=["|e", "|safe"],
    ),
    TaintSink(
        name="markup_safe",
        description="Markup constructor with untrusted data",
        vuln_type="XSS",
        severity="WARN",
        call_patterns=["Markup"],
        vulnerable_args=[0],
        sanitizer_patterns=["escape", "bleach.clean"],
    ),
    TaintSink(
        name="django_safe",
        description="Django mark_safe with untrusted data",
        vuln_type="XSS",
        severity="WARN",
        call_patterns=["mark_safe"],
        vulnerable_args=[0],
        sanitizer_patterns=["escape"],
    ),
]

# All default sinks combined
DEFAULT_SINKS = (
    SQL_INJECTION_SINKS +
    PATH_TRAVERSAL_SINKS +
    COMMAND_INJECTION_SINKS +
    SSRF_SINKS +
    XSS_SINKS
)


def get_sink_by_name(name: str) -> Optional[TaintSink]:
    """Get a taint sink by its name."""
    for sink in DEFAULT_SINKS:
        if sink.name == name:
            return sink
    return None


def get_sinks_by_vuln_type(vuln_type: str) -> List[TaintSink]:
    """Get all sinks for a specific vulnerability type."""
    return [s for s in DEFAULT_SINKS if s.vuln_type == vuln_type]


def is_sink_function(func_name: str) -> Optional[TaintSink]:
    """Check if a function name matches any sink pattern."""
    func_name_lower = func_name.lower()
    
    for sink in DEFAULT_SINKS:
        for pattern in sink.call_patterns:
            # Match full name or suffix
            if func_name == pattern or func_name.endswith("." + pattern.split(".")[-1]):
                return sink
    return None


def extract_call_name(node: ast.Call) -> Optional[str]:
    """Extract the full function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        # Build full path like "obj.method" or "module.submodule.func"
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None
