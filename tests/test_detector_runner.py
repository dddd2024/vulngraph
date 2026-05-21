"""第一阶段测试：验证 scan_file_with_builtin_detectors 能检测各类漏洞."""

from __future__ import annotations

import tempfile
from pathlib import Path

from detector.core.runner import scan_file_with_builtin_detectors


def _write_tmp(code: str, suffix: str = ".py") -> str:
    """将代码写入临时文件并返回路径."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(code)
    f.close()
    return f.name


class TestRunnerDetectsEval:
    """eval / exec / compile → Dangerous Code Execution."""

    def test_eval_detected(self):
        path = _write_tmp("eval(user_input)")
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Dangerous Code Execution" in types

    def test_exec_detected(self):
        path = _write_tmp("exec(code)")
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Dangerous Code Execution" in types


class TestRunnerDetectsCommandInjection:
    """subprocess shell=True → Command Injection."""

    def test_subprocess_shell_true(self):
        path = _write_tmp(
            "import subprocess\nsubprocess.run('ls', shell=True)"
        )
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Command Injection" in types

    def test_os_system(self):
        path = _write_tmp(
            "import os\nos.system('rm -rf /')"
        )
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Command Injection" in types


class TestRunnerDetectsUnsafeDeserialization:
    """pickle.loads → Unsafe Deserialization."""

    def test_pickle_loads(self):
        path = _write_tmp(
            "import pickle\ndata = pickle.loads(raw)"
        )
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Unsafe Deserialization" in types


class TestRunnerDetectsDebugMode:
    """DEBUG = True → Debug Mode Enabled."""

    def test_debug_assignment(self):
        path = _write_tmp("DEBUG = True")
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Debug Mode Enabled" in types

    def test_app_run_debug_true(self):
        path = _write_tmp(
            "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)"
        )
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Debug Mode Enabled" in types


class TestRunnerDetectsInsecureTLS:
    """requests.get(verify=False) → Insecure TLS Verification."""

    def test_requests_verify_false(self):
        path = _write_tmp(
            "import requests\nrequests.get('https://example.com', verify=False)"
        )
        findings = scan_file_with_builtin_detectors(path)
        types = {f["type"] for f in findings}
        assert "Insecure TLS Verification" in types


class TestRunnerFindingFields:
    """验证每个 finding 包含增强字段."""

    def test_fields_present(self):
        path = _write_tmp("eval(x)")
        findings = scan_file_with_builtin_detectors(path)
        assert len(findings) >= 1
        f = findings[0]
        assert "engine" in f
        assert "detector" in f
        assert "confidence" in f
        assert f["engine"] == "ast"

    def test_original_fields_preserved(self):
        path = _write_tmp("eval(x)")
        findings = scan_file_with_builtin_detectors(path)
        f = findings[0]
        assert "type" in f
        assert "file" in f
        assert "line" in f
        assert "severity" in f
