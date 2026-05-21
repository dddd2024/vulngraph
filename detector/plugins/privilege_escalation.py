"""Privilege Escalation 检测插件 – 包装 detector/vuln_detector.detect_privilege_escalation."""

from __future__ import annotations

from typing import Any

from detector.vuln_detector import detect_privilege_escalation


def run(file_path: str) -> list[dict[str, Any]]:
    """执行权限提升检测，返回标准 finding 列表."""
    findings = detect_privilege_escalation(file_path)
    for f in findings:
        f["engine"] = "plugin"
        f["detector"] = "privilege_escalation"
        f.setdefault("confidence", "medium")
    return findings
