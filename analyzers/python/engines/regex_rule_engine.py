"""Regex YAML 规则引擎 – 根据正则表达式对源文件进行模式匹配检测."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from analyzers.python.core.models import Finding, Rule

# 支持的 regex flags 映射
_FLAGS_MAP: dict[str, int] = {
    "DOTALL": re.DOTALL,
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
}


def _line_of(source: str, index: int) -> int:
    """根据字符索引计算行号."""
    return source[:index].count("\n") + 1


class RegexRuleEngine:
    """基于 YAML 正则规则的检测引擎."""

    def scan_file(self, file_path: str, rules: list[Rule]) -> list[Finding]:
        """对单个文件运行正则规则检测.

        Parameters
        ----------
        file_path:
            要检测的文件路径.
        rules:
            要应用的正则规则列表（engine == "regex"）.

        Returns
        -------
        list[Finding]
        """
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        findings: list[Finding] = []

        for rule in rules:
            pattern = rule.pattern
            regex_str = pattern.get("regex", "")
            if not regex_str:
                continue

            # 编译 flags
            flags = 0
            for flag_name in pattern.get("flags", []):
                flags |= _FLAGS_MAP.get(flag_name, 0)

            try:
                compiled = re.compile(regex_str, flags)
            except re.error:
                continue

            # 可选的排除条件
            exclude = pattern.get("exclude", "")

            for m in compiled.finditer(source):
                matched_text = m.group(0)
                if exclude and re.search(exclude, matched_text):
                    continue

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        type=rule.name,
                        file=file_path,
                        line=_line_of(source, m.start()),
                        symbol="",
                        severity=rule.severity,
                        engine="regex",
                        confidence=rule.confidence,
                        cwe=rule.cwe,
                        message=rule.message,
                    )
                )

        return findings