"""AST YAML 规则引擎 – 根据 YAML 规则定义对 Python 文件进行 AST 检测."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from detector.core.ast_utils import (
    contains_dynamic_value,
    keyword_is_false,
    keyword_is_true,
    literal_text,
    qualified_name,
    target_names,
)
from detector.core.models import Finding, Rule


def _match_call(rule: Rule, node: ast.Call) -> Finding | None:
    """匹配 pattern.kind == call 的规则."""
    pattern = rule.pattern
    names = pattern.get("names", [])
    if not names:
        return None

    call_name = qualified_name(node)
    if call_name not in names:
        return None

    # 检查 keywords 约束
    keywords = pattern.get("keywords", {})
    for kw_name, kw_val in keywords.items():
        if kw_val is True and not keyword_is_true(node, kw_name):
            return None
        if kw_val is False and not keyword_is_false(node, kw_name):
            return None

    return Finding(
        rule_id=rule.id,
        type=rule.name,
        file="",
        line=node.lineno,
        symbol=call_name,
        severity=rule.severity,
        engine="ast",
        confidence=rule.confidence,
        cwe=rule.cwe,
        message=rule.message,
    )


def _match_assignment(rule: Rule, node: ast.Assign | ast.AnnAssign) -> Finding | None:
    """匹配 pattern.kind == assignment 的规则."""
    pattern = rule.pattern
    value = node.value
    if value is None:
        return None

    # 检查 target_names 约束
    target_name_list = pattern.get("target_names", [])
    target_regex = pattern.get("target_regex", "")

    if isinstance(node, ast.Assign):
        all_names: list[str] = []
        for t in node.targets:
            all_names.extend(target_names(t))
    else:
        all_names = target_names(node.target)

    matched_name = ""
    if target_name_list:
        matched_name = next((n for n in all_names if n in target_name_list), "")
    if not matched_name and target_regex:
        regex = re.compile(target_regex)
        matched_name = next((n for n in all_names if regex.search(n)), "")

    if not matched_name and (target_name_list or target_regex):
        return None

    # 检查 value 约束
    expected_value = pattern.get("value")
    value_type = pattern.get("value_type")
    min_length = pattern.get("min_length", 0)

    if value_type == "string":
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        if min_length and len(value.value) < min_length:
            return None
        if expected_value is not None and value.value != expected_value:
            return None
    elif expected_value is not None:
        # 检查是否为布尔值 True
        if expected_value is True:
            if not (isinstance(value, ast.Constant) and value.value is True):
                return None
        elif expected_value is False:
            if not (isinstance(value, ast.Constant) and value.value is False):
                return None

    line = node.lineno
    if isinstance(node, ast.AnnAssign) and node.value:
        line = node.value.lineno

    return Finding(
        rule_id=rule.id,
        type=rule.name,
        file="",
        line=line,
        symbol=matched_name or all_names[0] if all_names else "",
        severity=rule.severity,
        engine="ast",
        confidence=rule.confidence,
        cwe=rule.cwe,
        message=rule.message,
    )


class AstRuleEngine:
    """基于 YAML 规则的 AST 检测引擎."""

    def scan_file(self, file_path: str, rules: list[Rule]) -> list[Finding]:
        """对单个文件运行 AST 规则检测.

        Parameters
        ----------
        file_path:
            要检测的 Python 文件路径.
        rules:
            要应用的 AST 规则列表（engine == "ast"）.

        Returns
        -------
        list[Finding]
        """
        source = Path(file_path).read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        for rule in rules:
            kind = rule.pattern.get("kind", "")
            for node in ast.walk(tree):
                try:
                    if kind == "call" and isinstance(node, ast.Call):
                        f = _match_call(rule, node)
                    elif kind == "assignment" and isinstance(node, (ast.Assign, ast.AnnAssign)):
                        f = _match_assignment(rule, node)
                    else:
                        f = None
                except Exception:
                    f = None
                if f is not None:
                    f.file = file_path
                    findings.append(f)
        return findings
