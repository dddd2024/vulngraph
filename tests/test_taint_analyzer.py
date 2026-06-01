"""
Tests for the advanced taint analyzer.

Verifies taint flow detection for:
  - SQL Injection
  - Path Traversal
  - Command Injection
  - SSRF
  - XSS
"""

import pytest

from analyzers.taint.taint_analyzer import (
    analyze_taint, flows_to_findings, analyze_code_unit, TaintFlow
)
from analyzers.taint.sources import DEFAULT_SOURCES
from analyzers.taint.sinks import DEFAULT_SINKS
from audit_core.models import CodeUnit


# ---------------------------------------------------------------------------
# Test data — Python code snippets with taint flows
# ---------------------------------------------------------------------------

SQL_INJECTION_FSTRING = '''
import sqlite3
from flask import request

def search_user():
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    user_input = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()
'''

SQL_INJECTION_CONCAT = '''
import sqlite3
from flask import request

def search_user():
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    user_input = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
'''

PATH_TRAVERSAL_CODE = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, 'r') as f:
        return f.read()
'''

COMMAND_INJECTION_CODE = '''
import os
from flask import request

def run_command():
    host = request.args.get("host")
    os.system("ping " + host)
'''

COMMAND_INJECTION_FSTRING = '''
import os
from flask import request

def run_command():
    host = request.args.get("host")
    os.system(f"ping {host}")
'''

SSRF_CODE = '''
import requests
from flask import request

def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text
'''

XSS_CODE = '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string(f"<h1>Hello {name}</h1>")
'''

# Sanitized (safe) code
SANITIZED_SQL_CODE = '''
import sqlite3
from flask import request

def search_user():
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    user_input = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()
'''

SANITIZED_COMMAND_CODE = '''
import subprocess
import shlex
from flask import request

def run_command():
    host = request.args.get("host")
    safe_host = shlex.quote(host)
    subprocess.run(["ping", safe_host])
'''

CLEAN_CODE = '''
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
'''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.py") -> CodeUnit:
    """Create a CodeUnit from source code string."""
    return CodeUnit(
        path=path,
        language="python",
        content=code,
        start_line=1,
        end_line=code.count("\n") + 1,
        metadata={},
    )


def _get_flows_by_type(flows: list[TaintFlow], vuln_type: str) -> list[TaintFlow]:
    """Get all flows of a specific vulnerability type."""
    return [f for f in flows if f.sink_type == vuln_type]


# ---------------------------------------------------------------------------
# Tests: SQL Injection detection
# ---------------------------------------------------------------------------

class TestSQLInjection:

    def test_detects_sql_injection_fstring(self):
        """Taint analyzer should detect SQL injection via f-string."""
        flows = analyze_taint(SQL_INJECTION_FSTRING)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        assert len(sql_flows) > 0, f"Expected SQL injection flows, got: {flows}"

    def test_detects_sql_injection_concat(self):
        """Taint analyzer should detect SQL injection via string concatenation."""
        flows = analyze_taint(SQL_INJECTION_CONCAT)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        assert len(sql_flows) > 0, f"Expected SQL injection flows, got: {flows}"

    def test_sql_flow_has_correct_source(self):
        """SQL injection flow should track the source variable."""
        flows = analyze_taint(SQL_INJECTION_FSTRING)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        assert any("user_input" in f.source for f in sql_flows)

    def test_sql_flow_has_correct_sink(self):
        """SQL injection flow should identify the sink function."""
        flows = analyze_taint(SQL_INJECTION_FSTRING)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        assert any("execute" in f.sink for f in sql_flows)

    def test_sql_severity_is_error(self):
        """SQL injection should have ERROR severity."""
        flows = analyze_taint(SQL_INJECTION_FSTRING)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        assert all(f.severity == "ERROR" for f in sql_flows)


# ---------------------------------------------------------------------------
# Tests: Path Traversal detection
# ---------------------------------------------------------------------------

class TestPathTraversal:

    def test_detects_path_traversal(self):
        """Taint analyzer should detect path traversal via open()."""
        flows = analyze_taint(PATH_TRAVERSAL_CODE)
        pt_flows = _get_flows_by_type(flows, "Path Traversal")

        assert len(pt_flows) > 0, f"Expected path traversal flows, got: {flows}"

    def test_path_traversal_source_tracking(self):
        """Path traversal should track from request.args to open()."""
        flows = analyze_taint(PATH_TRAVERSAL_CODE)
        pt_flows = _get_flows_by_type(flows, "Path Traversal")

        assert any("filename" in f.source for f in pt_flows)
        assert any("open" in f.sink for f in pt_flows)


# ---------------------------------------------------------------------------
# Tests: Command Injection detection
# ---------------------------------------------------------------------------

class TestCommandInjection:

    def test_detects_command_injection_concat(self):
        """Taint analyzer should detect command injection via string concat."""
        flows = analyze_taint(COMMAND_INJECTION_CODE)
        cmd_flows = _get_flows_by_type(flows, "Command Injection")

        assert len(cmd_flows) > 0, f"Expected command injection flows, got: {flows}"

    def test_detects_command_injection_fstring(self):
        """Taint analyzer should detect command injection via f-string."""
        flows = analyze_taint(COMMAND_INJECTION_FSTRING)
        cmd_flows = _get_flows_by_type(flows, "Command Injection")

        assert len(cmd_flows) > 0, f"Expected command injection flows, got: {flows}"

    def test_command_injection_os_system(self):
        """Command injection should detect os.system sink."""
        flows = analyze_taint(COMMAND_INJECTION_CODE)
        cmd_flows = _get_flows_by_type(flows, "Command Injection")

        assert any("system" in f.sink for f in cmd_flows)


# ---------------------------------------------------------------------------
# Tests: SSRF detection
# ---------------------------------------------------------------------------

class TestSSRF:

    def test_detects_ssrf(self):
        """Taint analyzer should detect SSRF via requests.get()."""
        flows = analyze_taint(SSRF_CODE)
        ssrf_flows = _get_flows_by_type(flows, "SSRF")

        assert len(ssrf_flows) > 0, f"Expected SSRF flows, got: {flows}"

    def test_ssrf_requests_sink(self):
        """SSRF should detect requests.get sink."""
        flows = analyze_taint(SSRF_CODE)
        ssrf_flows = _get_flows_by_type(flows, "SSRF")

        assert any("requests" in f.sink for f in ssrf_flows)


# ---------------------------------------------------------------------------
# Tests: XSS detection
# ---------------------------------------------------------------------------

class TestXSS:

    def test_detects_xss(self):
        """Taint analyzer should detect XSS via render_template_string."""
        flows = analyze_taint(XSS_CODE)
        xss_flows = _get_flows_by_type(flows, "XSS")

        assert len(xss_flows) > 0, f"Expected XSS flows, got: {flows}"


# ---------------------------------------------------------------------------
# Tests: Sanitization detection
# ---------------------------------------------------------------------------

class TestSanitization:

    def test_parameterized_query_is_sanitized(self):
        """Taint analyzer should not report sanitized SQL (parameterized query)."""
        flows = analyze_taint(SANITIZED_SQL_CODE)
        sql_flows = _get_flows_by_type(flows, "SQL Injection")

        # Should either have no flows or all flows should be marked as sanitized
        unsanitized = [f for f in sql_flows if not f.sanitized]
        assert len(unsanitized) == 0, "Parameterized query should be considered safe"

    @pytest.mark.skip(reason="Sanitizer tracking requires enhanced taint propagation - TODO")
    def test_shlex_quote_is_sanitized(self):
        """Taint analyzer should not report sanitized command (shlex.quote)."""
        flows = analyze_taint(SANITIZED_COMMAND_CODE)
        cmd_flows = _get_flows_by_type(flows, "Command Injection")

        unsanitized = [f for f in cmd_flows if not f.sanitized]
        assert len(unsanitized) == 0, "shlex.quote should sanitize command injection"


# ---------------------------------------------------------------------------
# Tests: Clean code
# ---------------------------------------------------------------------------

class TestCleanCode:

    def test_clean_code_produces_no_flows(self):
        """Clean code without sources or sinks should produce no taint flows."""
        flows = analyze_taint(CLEAN_CODE)

        assert len(flows) == 0, f"Clean code should have no flows, got: {flows}"


# ---------------------------------------------------------------------------
# Tests: RawFinding conversion
# ---------------------------------------------------------------------------

class TestFindingConversion:

    def test_flows_to_findings_conversion(self):
        """TaintFlow objects should convert to RawFinding correctly."""
        code_unit = _make_unit(SQL_INJECTION_FSTRING, "app.py")
        flows = analyze_taint(SQL_INJECTION_FSTRING, "app.py")
        findings = flows_to_findings(flows, code_unit)

        assert len(findings) > 0

        for finding in findings:
            assert finding.type in ["SQL Injection", "Path Traversal", "Command Injection", "SSRF", "XSS"]
            assert finding.file_path == "app.py"
            assert finding.engine == "taint"
            assert finding.rule_id.startswith("taint-")
            assert finding.message  # Should have a message

    def test_analyze_code_unit_integration(self):
        """analyze_code_unit should work end-to-end."""
        code_unit = _make_unit(SQL_INJECTION_FSTRING, "app.py")
        findings = analyze_code_unit(code_unit)

        sql_findings = [f for f in findings if "SQL" in f.type]
        assert len(sql_findings) > 0

    def test_non_python_unit_returns_empty(self):
        """Non-Python code units should return empty list."""
        code_unit = CodeUnit(
            path="app.js",
            language="javascript",
            content="console.log('hello');",
            start_line=1,
            end_line=1,
            metadata={},
        )
        findings = analyze_code_unit(code_unit)

        assert findings == []


# ---------------------------------------------------------------------------
# Tests: Source and Sink definitions
# ---------------------------------------------------------------------------

class TestSourceDefinitions:

    def test_default_sources_not_empty(self):
        """Default sources should be populated."""
        assert len(DEFAULT_SOURCES) > 0

    def test_has_flask_sources(self):
        """Should have Flask request sources."""
        flask_sources = [s for s in DEFAULT_SOURCES if "flask" in s.name]
        assert len(flask_sources) > 0

    def test_has_django_sources(self):
        """Should have Django request sources."""
        django_sources = [s for s in DEFAULT_SOURCES if "django" in s.name]
        assert len(django_sources) > 0


class TestSinkDefinitions:

    def test_default_sinks_not_empty(self):
        """Default sinks should be populated."""
        assert len(DEFAULT_SINKS) > 0

    def test_has_sql_sinks(self):
        """Should have SQL injection sinks."""
        sql_sinks = [s for s in DEFAULT_SINKS if s.vuln_type == "SQL Injection"]
        assert len(sql_sinks) > 0

    def test_has_command_sinks(self):
        """Should have command injection sinks."""
        cmd_sinks = [s for s in DEFAULT_SINKS if s.vuln_type == "Command Injection"]
        assert len(cmd_sinks) > 0

    def test_has_path_sinks(self):
        """Should have path traversal sinks."""
        path_sinks = [s for s in DEFAULT_SINKS if s.vuln_type == "Path Traversal"]
        assert len(path_sinks) > 0
