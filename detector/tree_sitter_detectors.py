"""
基于 Tree-sitter 的 JavaScript/TypeScript 漏洞检测器

支持检测的漏洞类型：
- SQL 注入 (SQL Injection)
- 命令注入 (Command Injection)
- 路径穿越 (Path Traversal)
- XSS 跨站脚本 (Cross-Site Scripting)
- 不安全的 eval() 使用

该模块作为 detector/vuln_detector.py 的扩展，不替代原有功能。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from parser.tree_sitter_parser import (
    LanguageType,
    ParsedCode,
    get_parser,
)


@dataclass
class Vulnerability:
    """漏洞信息"""
    type: str
    file: str
    line: int
    severity: str = "ERROR"
    confidence: str = "medium"
    symbol: str = ""
    detail: str = ""


# SQL 注入危险模式 - 关键词
SQL_DANGEROUS_METHODS = [
    "query", "execute", "exec", "raw", "sql",
    "run", "pool", "connection"
]

# 命令注入危险函数
CMD_DANGEROUS_FUNCTIONS = [
    "exec", "execsync", "spawn", "spawnsync",
    "execfile", "execfilesync", "fork", "system",
]

# XSS 危险模式
XSS_DANGEROUS_SINKS = [
    "innerhtml", "outerhtml", "insertadjacenthtml",
    "document.write", "document.writeln"
]

# Express 服务端响应 XSS sink
EXPRESS_XSS_SINKS = [
    "res.send", "res.write", "res.end", "res.render",
]

# Express 用户输入源
EXPRESS_USER_INPUT_SOURCES = [
    "req.query", "req.body", "req.params",
    "request.query", "request.body", "request.params",
]


class JavaScriptDetector:
    """
    JavaScript/TypeScript 漏洞检测器

    使用 Tree-sitter 进行 AST 分析，识别潜在的安全漏洞。
    """

    def __init__(self):
        self.parser = get_parser()

    def detect_file(self, file_path: str) -> list[Vulnerability]:
        """
        检测文件中的漏洞

        Args:
            file_path: 文件路径

        Returns:
            漏洞列表
        """
        parsed = self.parser.parse_file(file_path)
        if not parsed or parsed.language not in (
            LanguageType.JAVASCRIPT,
            LanguageType.TYPESCRIPT
        ):
            return []

        return self.detect_parsed(parsed)

    def detect_parsed(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        从解析结果中检测漏洞

        Args:
            parsed: 解析结果

        Returns:
            漏洞列表
        """
        vulnerabilities = []

        vulnerabilities.extend(self._detect_sql_injection(parsed))
        vulnerabilities.extend(self._detect_command_injection(parsed))
        vulnerabilities.extend(self._detect_path_traversal(parsed))
        vulnerabilities.extend(self._detect_xss(parsed))
        vulnerabilities.extend(self._detect_eval_usage(parsed))

        return vulnerabilities

    def _get_line_context(self, parsed: ParsedCode, line: int, context_lines: int = 2) -> str:
        """获取指定行及其上下文的代码"""
        lines = parsed.source.split("\n")
        start = max(0, line - 1 - context_lines)
        end = min(len(lines), line + context_lines)
        return "\n".join(lines[start:end])

    def _has_string_concatenation(self, parsed: ParsedCode, line: int) -> bool:
        """检查某行是否包含字符串拼接"""
        context = self._get_line_context(parsed, line, context_lines=0)
        # 检查 + 连接、模板字符串、字符串格式化等
        return ("+ " in context or " +" in context or
                "`" in context and "${" in context or
                "%" in context and "s" in context)

    def _has_user_input(self, parsed: ParsedCode, line: int) -> bool:
        """检查某行是否涉及用户输入"""
        context = self._get_line_context(parsed, line, context_lines=1).lower()
        user_input_keywords = [
            "req.", "request.", "params", "query", "body",
            "input", "postdata", "form", "files"
        ]
        return any(keyword in context for keyword in user_input_keywords)

    def _detect_sql_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """检测 SQL 注入"""
        findings = []

        for call in parsed.calls:
            callee_lower = call.callee.lower()

            # 检查是否调用了 SQL 相关方法
            is_sql_method = any(
                sql_method in callee_lower
                for sql_method in SQL_DANGEROUS_METHODS
            )

            if not is_sql_method:
                continue

            # 检查调用上下文是否涉及字符串拼接
            has_concat = self._has_string_concatenation(parsed, call.line)
            has_input = self._has_user_input(parsed, call.line)

            # 如果有 SQL 方法调用 + 字符串拼接 或 用户输入
            if has_concat or has_input:
                findings.append(Vulnerability(
                    type="SQL Injection",
                    file=parsed.file_path,
                    line=call.line,
                    severity="ERROR",
                    confidence="high" if (has_concat and has_input) else "medium",
                    symbol=call.callee,
                    detail=f"Potential SQL injection: {call.callee}() with string concatenation"
                ))

        return findings

    def _detect_command_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """检测命令注入"""
        findings = []

        for call in parsed.calls:
            callee_lower = call.callee.lower()

            # 检查是否是危险命令执行函数
            is_cmd_func = any(
                cmd_func in callee_lower
                for cmd_func in CMD_DANGEROUS_FUNCTIONS
            )

            if is_cmd_func:
                has_input = self._has_user_input(parsed, call.line)
                has_concat = self._has_string_concatenation(parsed, call.line)

                if has_input or has_concat:
                    findings.append(Vulnerability(
                        type="Command Injection",
                        file=parsed.file_path,
                        line=call.line,
                        severity="ERROR",
                        confidence="high" if has_input else "medium",
                        symbol=call.callee,
                        detail=f"Potential command injection: {call.callee}() with user input"
                    ))

        return findings

    def _detect_path_traversal(self, parsed: ParsedCode) -> list[Vulnerability]:
        """检测路径穿越"""
        findings = []

        dangerous_file_operations = [
            "readfile", "readfilesync", "writefile", "writefilesync",
            "appendfile", "appendfilesync", "createreadstream",
            "createwritestream", "readdir", "readdirsync",
            "stat", "statsync", "unlink", "rmdir"
        ]

        for call in parsed.calls:
            callee_lower = call.callee.lower()

            # 检查是否是文件操作函数
            is_file_op = any(
                op in callee_lower
                for op in dangerous_file_operations
            )

            if is_file_op:
                has_input = self._has_user_input(parsed, call.line)
                has_concat = self._has_string_concatenation(parsed, call.line)

                if has_input or has_concat:
                    findings.append(Vulnerability(
                        type="Path Traversal",
                        file=parsed.file_path,
                        line=call.line,
                        severity="ERROR",
                        confidence="high" if has_input else "medium",
                        symbol=call.callee,
                        detail=f"Potential path traversal: {call.callee}() with user-controlled path"
                    ))

        return findings

    def _detect_xss(self, parsed: ParsedCode) -> list[Vulnerability]:
        """检测 XSS 跨站脚本 - 包括赋值操作、函数调用和 Express 响应 sink"""
        findings = []
        source_lines = parsed.source.split("\n")

        # 方法1: 检查函数调用中的 XSS sink
        for call in parsed.calls:
            callee_lower = call.callee.lower()

            # 检查是否是 XSS 危险 sink (如 document.write)
            is_xss_sink = any(
                sink in callee_lower
                for sink in XSS_DANGEROUS_SINKS
            )

            if is_xss_sink:
                has_input = self._has_user_input(parsed, call.line)
                findings.append(Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    file=parsed.file_path,
                    line=call.line,
                    severity="ERROR",
                    confidence="high" if has_input else "medium",
                    symbol=call.callee,
                    detail=f"Potential XSS: {call.callee}() with unsanitized output"
                ))

        # 方法2: 检查赋值操作中的 innerHTML/outerHTML
        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            # 检查 innerHTML 或 outerHTML 赋值
            if ".innerhtml" in line_lower or ".outerhtml" in line_lower:
                # 检查是否包含用户输入
                has_input = self._has_user_input(parsed, i)

                # 提取属性名
                prop = "innerHTML" if ".innerhtml" in line_lower else "outerHTML"

                findings.append(Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high" if has_input else "medium",
                    symbol=prop,
                    detail=f"Potential XSS: {prop} assignment with unsanitized content"
                ))

        # 方法3: 检查 Express 服务端响应 sink (res.send/write/end/render)
        # 构建一个简单的函数级变量追踪，检测 req.query/req.body 赋值是否流入 sink
        self._detect_express_xss(parsed, source_lines, findings)

        return findings

    def _detect_express_xss(
        self,
        parsed: ParsedCode,
        source_lines: list[str],
        findings: list[Vulnerability],
    ) -> None:
        """检测 Express 服务端响应中的 XSS (res.send/write/end/render + 用户输入)."""
        source_lower = parsed.source.lower()

        # 快速检查：整个文件中是否存在 Express 用户输入源
        has_user_source = any(
            src in source_lower for src in EXPRESS_USER_INPUT_SOURCES
        )
        if not has_user_source:
            return

        # 检查是否存在 Express sink
        has_express_sink = any(
            sink in source_lower for sink in EXPRESS_XSS_SINKS
        )
        if not has_express_sink:
            return

        # 逐行扫描 Express sink 调用
        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            # 检查是否包含 Express sink
            matched_sink = None
            for sink in EXPRESS_XSS_SINKS:
                if sink in line_lower:
                    matched_sink = sink
                    break

            if matched_sink is None:
                continue

            # 检测模式1: sink 参数中包含字符串拼接 (+)
            has_concat = self._has_string_concatenation(parsed, i)

            # 检测模式2: 上下文中出现 req.query / req.body / req.params
            context = self._get_line_context(parsed, i, context_lines=3).lower()
            has_req_input = any(
                src in context for src in EXPRESS_USER_INPUT_SOURCES
            )

            # 检测模式3: 同一函数内变量来自 req.query/req.body 后流入 sink
            # 简化实现：检查 sink 行附近是否有变量引用了用户输入
            has_variable_flow = False
            if not has_req_input:
                # 扩大上下文到整个函数体（最多20行）
                func_context = self._get_line_context(parsed, i, context_lines=10).lower()
                has_variable_flow = any(
                    src in func_context for src in EXPRESS_USER_INPUT_SOURCES
                )

            if has_concat or has_req_input or has_variable_flow:
                confidence = "high" if (has_req_input or has_variable_flow) else "medium"
                findings.append(Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence=confidence,
                    symbol=matched_sink,
                    detail=(
                        f"Potential Express XSS: {matched_sink}() with "
                        f"{'user input' if (has_req_input or has_variable_flow) else 'string concatenation'}"
                    ),
                ))

    def _detect_eval_usage(self, parsed: ParsedCode) -> list[Vulnerability]:
        """检测不安全的 eval 使用"""
        findings = []

        dangerous_eval_functions = [
            "eval", "function(", "settimeout", "setinterval"
        ]

        for call in parsed.calls:
            callee_lower = call.callee.lower()

            # 检查是否是危险函数
            is_eval_like = any(
                eval_func in callee_lower
                for eval_func in dangerous_eval_functions
            )

            if is_eval_like:
                has_input = self._has_user_input(parsed, call.line)

                findings.append(Vulnerability(
                    type="Code Injection / Eval Usage",
                    file=parsed.file_path,
                    line=call.line,
                    severity="WARNING",
                    confidence="high" if has_input else "medium",
                    symbol=call.callee,
                    detail=f"Dangerous dynamic code execution: {call.callee}()"
                ))

        return findings


# 全局检测器实例
_global_detector: JavaScriptDetector | None = None


def get_detector() -> JavaScriptDetector:
    """获取全局检测器实例"""
    global _global_detector
    if _global_detector is None:
        _global_detector = JavaScriptDetector()
    return _global_detector


def detect_javascript_vulnerabilities(file_path: str) -> list[dict[str, Any]]:
    """
    便捷函数：检测 JavaScript 文件中的漏洞

    Args:
        file_path: 文件路径

    Returns:
        漏洞列表（字典格式）
    """
    detector = get_detector()
    vulns = detector.detect_file(file_path)

    return [
        {
            "type": v.type,
            "file": v.file,
            "line": v.line,
            "severity": v.severity,
            "confidence": v.confidence,
            "symbol": v.symbol,
            "detail": v.detail,
        }
        for v in vulns
    ]


# 导出支持的漏洞类型
SUPPORTED_VULN_TYPES = [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Cross-Site Scripting (XSS)",
    "Code Injection / Eval Usage",
]

SUPPORTED_LANGUAGES = [
    "javascript",
    "typescript",
]
