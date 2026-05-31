"""
Tests for the full audit pipeline detecting Python vulnerabilities.

Verifies that /scan → AuditOrchestrator → LegacyAnalyzerAdapter
can detect Python vulnerabilities end-to-end through the new pipeline,
without depending on main.py or analysis_engine.py.
"""

import pytest
from audit_core.models import CodeUnit, RawFinding, AuditResult
from audit_core.orchestrator import AuditOrchestrator
from audit_core.registry import AnalyzerRegistry
from analyzers.legacy_adapter import LegacyAnalyzerAdapter


# ---------------------------------------------------------------------------
# Vulnerable code snippets
# ---------------------------------------------------------------------------

SQL_INJECTION_CODE = '''
import sqlite3

def search_user(user_input):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()
'''

PATH_TRAVERSAL_CODE = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()
'''

COMMAND_INJECTION_CODE = '''
import os

def run_command(user_input):
    os.system(f"ls {user_input}")
'''

HARDCODED_SECRET_CODE = '''
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-abc123def456"

def connect():
    import sqlite3
    return sqlite3.connect("db.sqlite3")
'''

MULTI_VULN_CODE = '''
import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "admin_password_here"

@app.route("/search")
def search():
    q = request.args.get("q")
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")
    return cursor.fetchall()

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "done"

@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()
'''

CLEAN_CODE = '''
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
'''


# ---------------------------------------------------------------------------
# Tests: AuditOrchestrator with legacy adapter
# ---------------------------------------------------------------------------

class TestAuditPipelineDetectsPython:

    def test_scan_code_detects_sql_injection(self):
        """Pipeline should detect SQL injection via scan_code()."""
        orch = AuditOrchestrator()
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        assert isinstance(result, AuditResult)
        sql_findings = [f for f in result.findings if "SQL" in f.type]
        assert len(sql_findings) > 0, (
            f"Expected SQL Injection in findings, got types: "
            f"{[f.type for f in result.findings]}"
        )

    def test_scan_code_detects_path_traversal(self):
        """Pipeline should detect path traversal via scan_code()."""
        orch = AuditOrchestrator()
        result = orch.scan_code(PATH_TRAVERSAL_CODE, language="python")

        assert isinstance(result, AuditResult)
        pt_findings = [f for f in result.findings if "Path Traversal" in f.type]
        assert len(pt_findings) > 0, (
            f"Expected Path Traversal in findings, got types: "
            f"{[f.type for f in result.findings]}"
        )

    def test_scan_code_detects_command_injection(self):
        """Pipeline should detect command injection via scan_code()."""
        orch = AuditOrchestrator()
        result = orch.scan_code(COMMAND_INJECTION_CODE, language="python")

        assert isinstance(result, AuditResult)
        cmd_findings = [f for f in result.findings if "Command Injection" in f.type]
        assert len(cmd_findings) > 0, (
            f"Expected Command Injection in findings, got types: "
            f"{[f.type for f in result.findings]}"
        )

    def test_scan_code_detects_hardcoded_secret(self):
        """Pipeline should detect hardcoded secrets via scan_code()."""
        orch = AuditOrchestrator()
        result = orch.scan_code(HARDCODED_SECRET_CODE, language="python")

        assert isinstance(result, AuditResult)
        secret_findings = [
            f for f in result.findings
            if "Hardcoded Secret" in f.type or "secret" in f.type.lower()
        ]
        assert len(secret_findings) > 0, (
            f"Expected Hardcoded Secret in findings, got types: "
            f"{[f.type for f in result.findings]}"
        )

    def test_scan_code_clean_code_no_findings(self):
        """Clean code should produce no findings."""
        orch = AuditOrchestrator()
        result = orch.scan_code(CLEAN_CODE, language="python")

        assert isinstance(result, AuditResult)
        assert len(result.findings) == 0

    def test_scan_code_multi_vulnerability(self):
        """Pipeline should detect multiple vulnerability types in one scan."""
        orch = AuditOrchestrator()
        result = orch.scan_code(MULTI_VULN_CODE, language="python")

        assert isinstance(result, AuditResult)
        finding_types = set(f.type for f in result.findings)

        # Should detect at least 2 different types
        assert len(finding_types) >= 2, (
            f"Expected at least 2 different vulnerability types, got: {finding_types}"
        )

    def test_scan_returns_valid_audit_result(self):
        """scan_code() should return a valid AuditResult with all required fields."""
        orch = AuditOrchestrator()
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        # Check AuditResult structure
        assert hasattr(result, "summary")
        assert hasattr(result, "findings")
        assert hasattr(result, "evidence")
        assert hasattr(result, "agent_logs")

        # Check summary
        assert result.summary.total_code_units > 0
        assert result.summary.total_findings > 0
        assert result.summary.languages == ["python"]

    def test_findings_are_raw_finding_objects(self):
        """All findings should be RawFinding objects with required fields."""
        orch = AuditOrchestrator()
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        for finding in result.findings:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.message
            assert finding.engine

    def test_findings_have_evidence(self):
        """Findings should have evidence dict with legacy metadata."""
        orch = AuditOrchestrator()
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        for finding in result.findings:
            assert isinstance(finding.evidence, dict)

    def test_legacy_engine_not_main_or_analysis_engine(self):
        """Findings should come from modern engines, not from old pipeline."""
        orch = AuditOrchestrator()
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        for finding in result.findings:
            assert finding.engine in ("python", "pattern", "ast", "taint")


class TestAuditPipelineNoDependencyOnOldPipeline:

    def test_orchestrator_uses_registry(self):
        """AuditOrchestrator should use AnalyzerRegistry, not old pipeline."""
        orch = AuditOrchestrator()
        assert orch.registry is not None
        assert len(orch.registry.get_analyzers()) > 0

    def test_legacy_adapter_not_in_default_registry(self):
        """LegacyAnalyzerAdapter should NOT be in the default registry."""
        from audit_core.registry import build_default_registry
        registry = build_default_registry()
        adapter = registry.get("legacy")
        assert adapter is None

    def test_legacy_adapter_in_registry_with_enable_legacy(self):
        """LegacyAnalyzerAdapter should be in the registry when enable_legacy=True."""
        from audit_core.registry import build_default_registry
        registry = build_default_registry(enable_legacy=True)
        adapter = registry.get("legacy")
        assert adapter is not None
        assert isinstance(adapter, LegacyAnalyzerAdapter)

    def test_scan_does_not_import_analysis_engine(self):
        """AuditOrchestrator should not import analysis_engine."""
        import audit_core.orchestrator as orch_module
        source = orch_module.__file__
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        assert "analysis_engine" not in content
        assert "from main" not in content


class TestAuditPipelineWithCustomRegistry:

    def test_custom_registry_with_only_legacy(self):
        """Pipeline should work with only LegacyAnalyzerAdapter registered."""
        registry = AnalyzerRegistry()
        registry.register(LegacyAnalyzerAdapter())

        orch = AuditOrchestrator(registry=registry)
        result = orch.scan_code(SQL_INJECTION_CODE, language="python")

        assert isinstance(result, AuditResult)
        sql_findings = [f for f in result.findings if "SQL" in f.type]
        assert len(sql_findings) > 0
