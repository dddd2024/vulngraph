"""Path Traversal 检测插件 – 包装 detector/vuln_detector.detect_path_traversal."""

from __future__ import annotations

from typing import Any

from detector.vuln_detector import detect_path_traversal


def run(file_path: str) -> list[dict[str, Any]]:
    """执行路径穿越检测，返回标准 finding 列表."""
    findings = detect_path_traversal(file_path)
    for f in findings:
        f["engine"] = "plugin"
        f["detector"] = "path_traversal"
        f.setdefault("confidence", "medium")
    return findings
