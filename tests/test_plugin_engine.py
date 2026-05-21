"""第六阶段测试：验证 Plugin Engine 和 DetectorRunner."""

from __future__ import annotations

import tempfile

from detector.core.runner import DetectorRunner
from detector.engines.plugin_engine import PluginEngine


def _write_tmp(code: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    f.write(code)
    f.close()
    return f.name


class TestPluginEngine:
    def test_sql_injection_plugin(self):
        path = _write_tmp(
            'name = "admin"\n'
            'sql = "SELECT * FROM users WHERE name=\'" + name + "\'"\n'
            "conn.execute(sql)\n"
        )
        engine = PluginEngine()
        findings = engine.scan_file(path)
        types = {f["type"] for f in findings}
        assert "SQL Injection" in types

    def test_path_traversal_plugin(self):
        path = _write_tmp("with open(path, 'r') as f:\n    data = f.read()")
        engine = PluginEngine()
        findings = engine.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Path Traversal" in types

    def test_plugin_engine_field(self):
        path = _write_tmp("with open(path, 'r') as f:\n    data = f.read()")
        engine = PluginEngine()
        findings = engine.scan_file(path)
        assert len(findings) >= 1
        assert findings[0]["engine"] == "plugin"
        assert findings[0]["detector"] == "path_traversal"


class TestDetectorRunner:
    def test_runner_detects_eval(self):
        path = _write_tmp("eval(user_input)")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Dangerous Code Execution" in types

    def test_runner_detects_sql_injection_via_plugin(self):
        path = _write_tmp(
            'name = "admin"\n'
            'sql = "SELECT * FROM users WHERE name=\'" + name + "\'"\n'
            "conn.execute(sql)\n"
        )
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "SQL Injection" in types

    def test_runner_detects_path_traversal_via_plugin(self):
        path = _write_tmp("with open(path, 'r') as f:\n    data = f.read()")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Path Traversal" in types

    def test_runner_detects_subprocess_shell(self):
        path = _write_tmp("import subprocess\nsubprocess.run('ls', shell=True)")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Command Injection" in types

    def test_runner_detects_pickle(self):
        path = _write_tmp("import pickle\ndata = pickle.loads(raw)")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Unsafe Deserialization" in types

    def test_runner_detects_debug_mode(self):
        path = _write_tmp("DEBUG = True")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Debug Mode Enabled" in types

    def test_runner_detects_insecure_tls(self):
        path = _write_tmp("import requests\nrequests.get('https://x.com', verify=False)")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        types = {f["type"] for f in findings}
        assert "Insecure TLS Verification" in types

    def test_runner_finding_compatibility(self):
        path = _write_tmp("eval(x)")
        runner = DetectorRunner()
        findings = runner.scan_file(path)
        f = findings[0]
        assert "type" in f
        assert "file" in f
        assert "line" in f
        assert "severity" in f
        assert "engine" in f
