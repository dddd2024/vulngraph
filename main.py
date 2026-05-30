import json
from pathlib import Path
from typing import Any

from detector.impact_analyzer import find_impacted_modules
from detector.vuln_detector import detect_all
from parser.call_graph import build_call_graph, export_edges
from parser.repo_scanner import scan_repo


def run_pipeline(project_root: str = ".") -> dict[str, Any]:
    """
    运行漏洞检测 pipeline。

    该函数执行以下步骤：
    1. 扫描代码仓库
    2. 构建调用图
    3. 检测所有漏洞
    4. 查找受影响的模块
    5. 导出调用图边数据
    6. 保存检测结果到 JSON 文件
    """
    root = Path(project_root).resolve()

    # 1. 扫描代码仓库
    files = scan_repo(str(root / "repo"))

    # 2. 构建调用图
    graph = build_call_graph(str(root / "repo"))

    # 3. 检测所有漏洞
    findings = detect_all(str(root / "repo"))

    # 4. 查找受影响的模块（仅在有漏洞时）
    target = None
    impact: list[dict[str, Any]] = []
    if findings:
        target = next(
            (f for f in findings if f["type"] == "SQL Injection"), findings[0]
        )
        impact = find_impacted_modules(graph, target.get("symbol", "search_user"))

    # 5. 导出调用图边数据
    graph_edges = export_edges(graph)

    # 6. 构建检测结果
    result: dict[str, Any] = {
        "report_mode": "detect-only",
        "target": target,
        "impact": impact,
        "graph_edges": graph_edges,
        "findings": findings,
        "scanned_files": len(files) if files else 0,
    }

    if not findings:
        result["message"] = "No vulnerabilities detected."

    # 7. 保存结果到 JSON 文件
    (root / "pipeline_result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return result


if __name__ == "__main__":
    output = run_pipeline(".")
    print(json.dumps(output, ensure_ascii=False, indent=2))
