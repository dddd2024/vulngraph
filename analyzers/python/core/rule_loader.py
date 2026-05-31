"""YAML 规则加载器 – 从 analyzers/python/rules/ 目录加载 YAML 规则文件.

支持的引擎类型：
- ast: AST YAML 规则引擎
- regex: 正则表达式规则引擎
- taint: 污点流分析引擎
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from analyzers.python.core.models import Rule

# 规则目录（相对于 analyzers/python/）
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _parse_rule(raw: dict[str, Any]) -> Rule:
    """将 YAML 中的单个规则字典转换为 Rule 对象.

    对于 taint 引擎规则，将 sources/sinks/sanitizers 放入 pattern 字段。
    """
    engine = raw.get("engine", "ast")
    pattern = raw.get("pattern", {})

    # 对于 taint 引擎，确保 pattern 包含污点配置
    if engine == "taint":
        # 如果 pattern 中没有污点配置，从 raw 中提取
        if not pattern.get("sources") and raw.get("sources"):
            pattern["sources"] = raw["sources"]
        if not pattern.get("sinks") and raw.get("sinks"):
            pattern["sinks"] = raw["sinks"]
        if not pattern.get("sanitizers") and raw.get("sanitizers"):
            pattern["sanitizers"] = raw["sanitizers"]

    return Rule(
        id=raw.get("id", ""),
        name=raw.get("name", ""),
        type=raw.get("type", "ast"),
        severity=raw.get("severity", "ERROR"),
        engine=engine,
        language=raw.get("language", "python"),
        cwe=raw.get("cwe", ""),
        confidence=raw.get("confidence", "medium"),
        message=raw.get("message", ""),
        enabled=raw.get("enabled", True),
        pattern=pattern,
    )


def load_yaml_rules(rules_dir: Path | str | None = None) -> list[Rule]:
    """从指定目录加载所有 YAML 规则文件.

    Parameters
    ----------
    rules_dir:
        规则目录路径。为 ``None`` 时使用默认路径 ``analyzers/python/rules/``.

    Returns
    -------
    list[Rule]
        所有已启用的规则。
    """
    if rules_dir is None:
        rules_dir = _RULES_DIR
    else:
        rules_dir = Path(rules_dir)

    rules: list[Rule] = []
    if not rules_dir.is_dir():
        return rules

    for yml_file in sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for raw_rule in data.get("rules", []):
            if not isinstance(raw_rule, dict):
                continue
            rule = _parse_rule(raw_rule)
            if rule.enabled:
                rules.append(rule)
    return rules