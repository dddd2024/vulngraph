"""第五阶段测试：验证 AST YAML 规则引擎."""

from __future__ import annotations

import tempfile

from detector.core.rule_loader import load_yaml_rules
from detector.engines.ast_rule_engine import AstRuleEngine


def _write_tmp(code: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    f.write(code)
    f.close()
    return f.name


_ENGINE = AstRuleEngine()


class TestAstRuleEngineEval:
    def test_eval_detected(self):
        path = _write_tmp("eval(user_input)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-DCE-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Dangerous Code Execution"

    def test_exec_detected(self):
        path = _write_tmp("exec(code)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-DCE-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1


class TestAstRuleEngineCommandInjection:
    def test_subprocess_shell_true(self):
        path = _write_tmp("import subprocess\nsubprocess.run('ls', shell=True)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-CI-002"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Command Injection"

    def test_os_system(self):
        path = _write_tmp("import os\nos.system('rm -rf /')")
        rules = [r for r in load_yaml_rules() if r.id == "AST-CI-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1


class TestAstRuleEngineDeserialization:
    def test_pickle_loads(self):
        path = _write_tmp("import pickle\ndata = pickle.loads(raw)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-UD-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Unsafe Deserialization"


class TestAstRuleEngineHardcodedSecret:
    def test_password_assignment(self):
        path = _write_tmp('password = "s3cret"')
        rules = [r for r in load_yaml_rules() if r.id == "AST-HS-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Hardcoded Secret"


class TestAstRuleEngineWeakCrypto:
    def test_hashlib_md5(self):
        path = _write_tmp("import hashlib\nhashlib.md5(b'data')")
        rules = [r for r in load_yaml_rules() if r.id == "AST-WC-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Weak Cryptography"


class TestAstRuleEngineDebugMode:
    def test_debug_true(self):
        path = _write_tmp("DEBUG = True")
        rules = [r for r in load_yaml_rules() if r.id == "AST-DM-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Debug Mode Enabled"


class TestAstRuleEngineInsecureTLS:
    def test_requests_verify_false(self):
        path = _write_tmp("import requests\nrequests.get('https://x.com', verify=False)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-TLS-001"]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].type == "Insecure TLS Verification"


class TestAstRuleEngineFindingFields:
    def test_to_dict_compatibility(self):
        path = _write_tmp("eval(x)")
        rules = [r for r in load_yaml_rules() if r.id == "AST-DCE-001"]
        findings = _ENGINE.scan_file(path, rules)
        d = findings[0].to_dict()
        assert "type" in d
        assert "file" in d
        assert "line" in d
        assert "symbol" in d
        assert "severity" in d
        assert "engine" in d
