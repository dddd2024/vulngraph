"""SQL Injection 检测插件 – 包装 detector/vuln_detector.detect_sql_injection."""

from __future__ import annotations

from typing import Any

from detector.vuln_detector import detect_sql_injection


def run(file_path: str) -> list[dict[str, Any]]:
    """执行 SQL 注入检测，返回标准 finding 列表."""
    findings = detect_sql_injection(file_path)
    for f in findings:
        f["engine"] = "plugin"
        f["detector"] = "sql_injection"
        f.setdefault("confidence", "high")
    return findings
