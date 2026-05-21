"""第四阶段测试：验证 YAML 规则加载."""

from __future__ import annotations

import tempfile
from pathlib import Path

from detector.core.rule_loader import load_yaml_rules


class TestRuleLoader:
    def test_load_from_directory(self):
        """验证能从 detector/rules/ast/ 加载 YAML 规则."""
        rules = load_yaml_rules()
        assert len(rules) >= 7
        rule_ids = {r.id for r in rules}
        assert "AST-DCE-001" in rule_ids
        assert "AST-CI-001" in rule_ids
        assert "AST-UD-001" in rule_ids
        assert "AST-HS-001" in rule_ids
        assert "AST-WC-001" in rule_ids
        assert "AST-DM-001" in rule_ids
        assert "AST-TLS-001" in rule_ids

    def test_load_from_custom_directory(self):
        """验证能从自定义目录加载."""
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            yml_file = rules_dir / "test.yml"
            yml_file.write_text(
                "rules:\n"
                "  - id: TEST-001\n"
                "    name: Test Rule\n"
                "    type: ast\n"
                "    severity: ERROR\n"
                "    engine: ast\n"
                "    pattern:\n"
                "      kind: call\n"
                "      names: [eval]\n",
                encoding="utf-8",
            )
            rules = load_yaml_rules(rules_dir)
            assert len(rules) == 1
            assert rules[0].id == "TEST-001"

    def test_disabled_rule_skipped(self):
        """验证 disabled 规则被跳过."""
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp)
            yml_file = rules_dir / "disabled.yml"
            yml_file.write_text(
                "rules:\n"
                "  - id: DISABLED-001\n"
                "    name: Disabled Rule\n"
                "    type: ast\n"
                "    severity: ERROR\n"
                "    engine: ast\n"
                "    enabled: false\n"
                "    pattern:\n"
                "      kind: call\n"
                "      names: [eval]\n",
                encoding="utf-8",
            )
            rules = load_yaml_rules(rules_dir)
            assert len(rules) == 0

    def test_nonexistent_directory(self):
        """验证不存在的目录返回空列表."""
        rules = load_yaml_rules("/nonexistent/path")
        assert rules == []
