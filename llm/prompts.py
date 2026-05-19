from __future__ import annotations

from typing import Any


def build_patch_prompt(vuln: dict[str, Any], original: str, rule_diff: str) -> str:
    return (
        "你是代码安全修复助手。请针对以下漏洞给出简短补丁（尽量 unified diff）。\n\n"
        f"漏洞类型: {vuln['type']}\n"
        f"文件: {vuln['file']}:{vuln['line']}\n"
        f"原始代码片段:\n{original[:1200]}\n\n"
        f"规则补丁候选:\n{rule_diff[:1200]}\n"
    )


def build_graph_insight_prompt(
    vuln: dict[str, Any],
    cwe: str,
    cases: list[dict[str, str]],
    fixes: list[str],
) -> str:
    return (
        "你是漏洞知识图谱生成助手。请基于以下公开优秀案例，生成一段 2-3 句的中文安全知识摘要，"
        "用于连接“漏洞 -> 案例 -> 修复模式”。要求：简洁、可执行、不要编造。\n\n"
        f"漏洞类型: {vuln.get('type', 'Unknown')}\n"
        f"CWE: {cwe}\n"
        f"案例参考: {cases}\n"
        f"修复模式: {fixes}\n"
        f"当前漏洞上下文: file={vuln.get('file', '')}, line={vuln.get('line', 0)}, severity={vuln.get('severity', '')}"
    )
