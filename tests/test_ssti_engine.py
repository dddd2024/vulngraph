"""
Tests for Python SSTI (Server-Side Template Injection) engine.

Verifies detection of:
- Jinja2 template injection
- Mako template injection
- string.Template injection
- Tornado template injection
"""

import pytest

from analyzers.python.engines.ssti_engine import SSTIEngine, analyze_code_unit
from audit_core.models import CodeUnit


# ---------------------------------------------------------------------------
# Test data — Python code snippets with SSTI vulnerabilities
# ---------------------------------------------------------------------------

JINJA2_SSTI_CODE = '''
from flask import request
from jinja2 import Template

def render_user_template():
    user_template = request.args.get('template')
    template = Template(user_template)
    return template.render()
'''

JINJA2_FROM_STRING_CODE = '''
from flask import request
from jinja2 import Environment

env = Environment()

def render_from_string():
    user_input = request.form.get('content')
    template = env.from_string(user_input)
    return template.render()
'''

MAKO_SSTI_CODE = '''
from flask import request
from mako.template import Template

def render_mako():
    user_template = request.args.get('template')
    template = Template(user_template)
    return template.render()
'''

STRING_TEMPLATE_CODE = '''
from flask import request
from string import Template

def render_string_template():
    user_template = request.args.get('template')
    template = Template(user_template)
    return template.substitute(name="test")
'''

TORNADO_SSTI_CODE = '''
from flask import request
from tornado.template import Template

def render_tornado():
    user_template = request.args.get('template')
    template = Template(user_template)
    return template.generate()
'''

# Safe code — should not trigger
SAFE_JINJA2_CODE = '''
from jinja2 import Template

def render_safe():
    template = Template("Hello {{ name }}!")
    return template.render(name="World")
'''

SAFE_STRING_TEMPLATE_CODE = '''
from string import Template

def render_safe():
    template = Template("Hello $name!")
    return template.substitute(name="World")
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


# ---------------------------------------------------------------------------
# Tests: Jinja2 SSTI
# ---------------------------------------------------------------------------

class TestJinja2SSTI:

    def test_detects_jinja2_template_injection(self):
        """Should detect Jinja2 template injection via Template(user_input).render()"""
        engine = SSTIEngine()
        findings = engine.scan_code(JINJA2_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0, "Should detect Jinja2 SSTI"

    def test_jinja2_finding_has_cwe1336(self):
        """Jinja2 SSTI finding should reference CWE-1336"""
        engine = SSTIEngine()
        findings = engine.scan_code(JINJA2_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert any(f.cwe == "CWE-1336" for f in ssti_findings)

    def test_detects_jinja2_from_string(self):
        """Should detect Jinja2 from_string() SSTI"""
        engine = SSTIEngine()
        findings = engine.scan_code(JINJA2_FROM_STRING_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0, "Should detect Jinja2 from_string SSTI"

    def test_jinja2_severity_is_error(self):
        """Jinja2 SSTI should have ERROR severity"""
        engine = SSTIEngine()
        findings = engine.scan_code(JINJA2_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert all(f.severity == "ERROR" for f in ssti_findings)


# ---------------------------------------------------------------------------
# Tests: Mako SSTI
# ---------------------------------------------------------------------------

class TestMakoSSTI:

    def test_detects_mako_template_injection(self):
        """Should detect Mako template injection"""
        engine = SSTIEngine()
        findings = engine.scan_code(MAKO_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0, "Should detect Mako SSTI"

    def test_mako_rule_id(self):
        """Mako SSTI should have correct rule_id"""
        engine = SSTIEngine()
        findings = engine.scan_code(MAKO_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert any(f.rule_id == "PY_SSTI_003" for f in ssti_findings)


# ---------------------------------------------------------------------------
# Tests: string.Template SSTI
# ---------------------------------------------------------------------------

class TestStringTemplateSSTI:

    def test_detects_string_template_injection(self):
        """Should detect string.Template injection"""
        engine = SSTIEngine()
        findings = engine.scan_code(STRING_TEMPLATE_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0, "Should detect string.Template SSTI"

    def test_string_template_severity_is_warn(self):
        """string.Template SSTI should have WARN severity (lower risk)"""
        engine = SSTIEngine()
        findings = engine.scan_code(STRING_TEMPLATE_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert all(f.severity == "WARN" for f in ssti_findings)


# ---------------------------------------------------------------------------
# Tests: Tornado SSTI
# ---------------------------------------------------------------------------

class TestTornadoSSTI:

    def test_detects_tornado_template_injection(self):
        """Should detect Tornado template injection"""
        engine = SSTIEngine()
        findings = engine.scan_code(TORNADO_SSTI_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0, "Should detect Tornado SSTI"


# ---------------------------------------------------------------------------
# Tests: Safe code (no findings expected)
# ---------------------------------------------------------------------------

class TestSafeCode:

    def test_safe_jinja2_no_findings(self):
        """Safe Jinja2 usage should not trigger findings"""
        engine = SSTIEngine()
        findings = engine.scan_code(SAFE_JINJA2_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) == 0, "Safe Jinja2 should not trigger"

    def test_safe_string_template_no_findings(self):
        """Safe string.Template usage should not trigger findings"""
        engine = SSTIEngine()
        findings = engine.scan_code(SAFE_STRING_TEMPLATE_CODE, "app.py")

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) == 0, "Safe string.Template should not trigger"


# ---------------------------------------------------------------------------
# Tests: analyze_code_unit integration
# ---------------------------------------------------------------------------

class TestAnalyzeCodeUnit:

    def test_analyze_code_unit_integration(self):
        """analyze_code_unit should work end-to-end"""
        code_unit = _make_unit(JINJA2_SSTI_CODE, "app.py")
        findings = analyze_code_unit(code_unit)

        ssti_findings = [f for f in findings if "SSTI" in f.type]
        assert len(ssti_findings) > 0

    def test_non_python_unit_returns_empty(self):
        """Non-Python code units should return empty list"""
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

    def test_finding_has_correct_engine(self):
        """Finding should have engine field set"""
        code_unit = _make_unit(JINJA2_SSTI_CODE, "app.py")
        findings = analyze_code_unit(code_unit)

        for finding in findings:
            assert finding.engine is not None
            assert finding.file_path == "app.py"
