"""第七阶段测试：验证 Regex YAML 规则引擎."""

from __future__ import annotations

import tempfile

from detector.core.rule_loader import load_yaml_rules
from detector.engines.regex_rule_engine import RegexRuleEngine


def _write_tmp(code: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    f.write(code)
    f.close()
    return f.name


_ENGINE = RegexRuleEngine()


class TestRegexEngineSQLInjection:
    def test_f_string_sql(self):
        path = _write_tmp('conn.execute(f"SELECT * FROM users WHERE name={name}")')
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "SQL" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        types = {f.type for f in findings}
        assert "SQL Injection" in types

    def test_percent_format_sql(self):
        path = _write_tmp('conn.execute("SELECT * FROM users WHERE id=%s" % user_id)')
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "SQL" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        types = {f.type for f in findings}
        assert "SQL Injection" in types


class TestRegexEnginePathTraversal:
    def test_open_request_args(self):
        path = _write_tmp("data = open(request.args.get('file'), 'r').read()")
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "Path" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        types = {f.type for f in findings}
        assert "Path Traversal" in types

    def test_open_path_variable(self):
        path = _write_tmp("with open(path, 'r') as f:\n    data = f.read()")
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "Path" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        types = {f.type for f in findings}
        assert "Path Traversal" in types


class TestRegexEnginePrivilegeEscalation:
    def test_admin_route(self):
        path = _write_tmp("@app.route('/admin')\ndef admin_panel():\n    pass")
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "Privilege" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        types = {f.type for f in findings}
        assert "Privilege Escalation" in types


class TestRegexEngineFields:
    def test_engine_field(self):
        path = _write_tmp('conn.execute(f"SELECT * FROM users WHERE name={name}")')
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "SQL" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        assert len(findings) >= 1
        assert findings[0].engine == "regex"

    def test_to_dict_compatibility(self):
        path = _write_tmp('conn.execute(f"SELECT * FROM users WHERE name={name}")')
        rules = [r for r in load_yaml_rules() if r.engine == "regex" and "SQL" in r.name]
        findings = _ENGINE.scan_file(path, rules)
        d = findings[0].to_dict()
        assert "type" in d
        assert "file" in d
        assert "line" in d
        assert "severity" in d
        assert "engine" in d
