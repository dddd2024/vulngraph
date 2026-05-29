"""污点分析引擎 – 基于 AST 的污点传播追踪检测.

第一版特性：
- 单文件、函数内污点传播
- 支持赋值传播、字符串拼接、f-string、format、函数调用返回值保守传播
- 检测 SQL Injection、Path Traversal、Command Injection 三类漏洞
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from detector.core.ast_utils import qualified_name, keyword_is_false, keyword_is_true
from detector.core.models import Rule
from detector.core.taint_models import (
    TaintFinding,
    TaintRuleConfig,
    TaintTraceStep,
    TaintVariable,
)


def _get_node_line(node: ast.AST) -> int:
    """获取 AST 节点的行号."""
    return getattr(node, "lineno", 0)


def _get_node_col(node: ast.AST) -> int:
    """获取 AST 节点的列号."""
    return getattr(node, "col_offset", 0)


def _get_code_snippet(source: str, line: int, max_len: int = 80) -> str:
    """获取指定行的代码片段."""
    lines = source.splitlines()
    if 0 < line <= len(lines):
        snippet = lines[line - 1].strip()
        if len(snippet) > max_len:
            snippet = snippet[:max_len] + "..."
        return snippet
    return ""


def _match_source_pattern(node: ast.Call, source_patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    """检查节点是否匹配污点源模式."""
    call_name = qualified_name(node)
    for pattern in source_patterns:
        pattern_name = pattern.get("name", "")
        # 支持精确匹配和前缀匹配
        if call_name == pattern_name or call_name.endswith("." + pattern_name):
            return pattern
        # 特殊处理 request.args.get 等链式调用
        if pattern_name.startswith("request.") and call_name.startswith("request."):
            return pattern
    return None


def _match_sink_pattern(node: ast.Call, sink_patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    """检查节点是否匹配污点汇模式."""
    call_name = qualified_name(node)
    for pattern in sink_patterns:
        pattern_name = pattern.get("name", "")
        if call_name == pattern_name or call_name.endswith("." + pattern_name):
            return pattern
        # 处理方法调用（如 cursor.execute）
        if "." in pattern_name and call_name.endswith(pattern_name.split(".")[-1]):
            return pattern
    return None


def _match_sanitizer_pattern(node: ast.Call, sanitizer_patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    """检查节点是否匹配净化器模式."""
    call_name = qualified_name(node)
    for pattern in sanitizer_patterns:
        pattern_name = pattern.get("name", "")
        if call_name == pattern_name or call_name.endswith("." + pattern_name):
            return pattern
    return None


def _is_subprocess_safe(node: ast.Call) -> bool:
    """检查 subprocess 调用是否安全（shell=False 且使用列表参数）."""
    call_name = qualified_name(node)
    if not call_name.startswith("subprocess."):
        return False

    # 检查 shell=False
    if not keyword_is_false(node, "shell"):
        return False

    # 检查第一个参数是否为列表
    if node.args:
        first_arg = node.args[0]
        if isinstance(first_arg, (ast.List, ast.Tuple)):
            return True

    return False


def _is_sql_safe(node: ast.Call) -> bool:
    """检查 SQL 执行是否安全（使用参数化查询）."""
    call_name = qualified_name(node)
    if not any(call_name.endswith(s) for s in ["execute", "executemany"]):
        return False

    # 检查是否有第二个参数（参数列表）
    if len(node.args) >= 2:
        return True

    # 检查 keywords 中是否有 params
    for kw in node.keywords:
        if kw.arg == "parameters" or kw.arg == "params":
            return True

    return False


def _extract_variable_name(node: ast.AST) -> str:
    """从 AST 节点提取变量名."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _extract_variable_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Subscript):
        base = _extract_variable_name(node.value)
        if base:
            return f"{base}[...]"
        return "[...]"
    return ""


def _contains_tainted_variable(node: ast.AST, tainted_vars: dict[str, TaintVariable]) -> list[TaintVariable]:
    """检查 AST 节点是否包含污点变量，返回所有涉及的污点变量."""
    found: list[TaintVariable] = []

    def _visit(n: ast.AST) -> None:
        if isinstance(n, ast.Name):
            if n.id in tainted_vars:
                found.append(tainted_vars[n.id])
        elif isinstance(n, ast.Attribute):
            # 处理属性访问，如 request.args
            base_name = _extract_variable_name(n.value)
            full_name = f"{base_name}.{n.attr}" if base_name else n.attr
            # 检查完整名称或基础名称
            if full_name in tainted_vars:
                found.append(tainted_vars[full_name])
            elif base_name in tainted_vars:
                found.append(tainted_vars[base_name])
        elif isinstance(n, ast.Subscript):
            # 下标访问，如 request.args['key']
            _visit(n.value)
        # 递归遍历子节点
        for child in ast.iter_child_nodes(n):
            _visit(child)

    _visit(node)
    return found


def _propagate_taint_through_binop(
    node: ast.BinOp,
    tainted_vars: dict[str, TaintVariable],
    source: str,
    source_line: int,
    file_path: str,
    source_code: str,
) -> list[TaintVariable]:
    """通过二元操作（字符串拼接）传播污点."""
    found = _contains_tainted_variable(node, tainted_vars)
    return found


def _propagate_taint_through_joinedstr(
    node: ast.JoinedStr,
    tainted_vars: dict[str, TaintVariable],
    source: str,
    source_line: int,
    file_path: str,
    source_code: str,
) -> list[TaintVariable]:
    """通过 f-string 传播污点."""
    found: list[TaintVariable] = []
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            tainted = _contains_tainted_variable(value.value, tainted_vars)
            found.extend(tainted)
    return found


def _propagate_taint_through_call(
    node: ast.Call,
    tainted_vars: dict[str, TaintVariable],
    sanitizer_patterns: list[dict[str, Any]],
    source: str,
    source_line: int,
    file_path: str,
    source_code: str,
) -> tuple[list[TaintVariable], bool, str]:
    """通过函数调用传播污点，返回 (污点变量列表, 是否净化, 净化器名称)."""
    # 首先检查是否是净化器
    sanitizer_pattern = _match_sanitizer_pattern(node, sanitizer_patterns)
    if sanitizer_pattern:
        # 检查净化器条件
        sanitizer_name = sanitizer_pattern.get("name", "")
        condition = sanitizer_pattern.get("condition", "")

        # 特殊处理 subprocess 安全调用
        if condition == "shell_false_list_args" and _is_subprocess_safe(node):
            return [], True, sanitizer_name

        # 特殊处理 SQL 参数化查询
        if condition == "has_params" and _is_sql_safe(node):
            return [], True, sanitizer_name

        # 一般净化器（如 secure_filename, shlex.quote）
        if not condition or condition == "":
            # 检查调用参数是否包含污点
            found = _contains_tainted_variable(node, tainted_vars)
            if found:
                return [], True, sanitizer_name

    # 检查调用参数是否包含污点（保守传播）
    found = _contains_tainted_variable(node, tainted_vars)

    # 对于返回值，保守地认为如果参数被污染，返回值也被污染
    return found, False, ""


class FunctionTaintAnalyzer(ast.NodeVisitor):
    """函数级污点分析器，在单个函数内追踪污点传播."""

    def __init__(
        self,
        file_path: str,
        source_code: str,
        rule_config: TaintRuleConfig,
    ) -> None:
        self.file_path = file_path
        self.source_code = source_code
        self.rule_config = rule_config

        # 污点变量状态
        self._tainted_vars: dict[str, TaintVariable] = {}

        # 检测到的漏洞
        self._findings: list[TaintFinding] = []

        # 当前函数名
        self._current_function: str = ""

        # 源配置
        self._source_patterns = rule_config.sources
        self._sink_patterns = rule_config.sinks
        self._sanitizer_patterns = rule_config.sanitizers

    def analyze(self, tree: ast.AST) -> list[TaintFinding]:
        """分析 AST 树，返回检测到的漏洞."""
        self.visit(tree)
        return self._findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """处理函数定义."""
        # 重置污点状态
        old_tainted = dict(self._tainted_vars)
        old_function = self._current_function

        self._tainted_vars = {}
        self._current_function = node.name

        # 遍历函数体
        for stmt in node.body:
            self.visit(stmt)

        # 恢复状态
        self._tainted_vars = old_tainted
        self._current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """处理异步函数定义."""
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """处理赋值语句，传播污点."""
        # 分析赋值值
        value = node.value
        new_taints: list[TaintVariable] = []
        sanitized = False
        sanitizer_name = ""

        # 检查是否是污点源
        if isinstance(value, ast.Call):
            source_pattern = _match_source_pattern(value, self._source_patterns)
            if source_pattern:
                # 这是一个污点源
                source_name = source_pattern.get("name", "")
                source_desc = source_pattern.get("description", "")
                source_line = _get_node_line(value)

                # 创建污点变量
                for target in node.targets:
                    target_names = self._extract_target_names(target)
                    for name in target_names:
                        trace_step = TaintTraceStep(
                            file=self.file_path,
                            line=source_line,
                            col=_get_node_col(value),
                            node_type="source",
                            code_snippet=_get_code_snippet(self.source_code, source_line),
                            variable=name,
                            description=f"污点源: {source_desc}",
                        )
                        taint_var = TaintVariable(
                            name=name,
                            tainted=True,
                            source=source_name,
                            source_line=source_line,
                            trace_steps=[trace_step],
                        )
                        self._tainted_vars[name] = taint_var
                        new_taints.append(taint_var)
            else:
                # 检查污点传播或净化
                found, sanitized, sanitizer_name = _propagate_taint_through_call(
                    value, self._tainted_vars, self._sanitizer_patterns,
                    "", 0, self.file_path, self.source_code
                )
                if sanitized:
                    # 净化后的值，清除污点
                    pass
                elif found:
                    # 传播污点
                    new_taints = found

        # 检查字符串拼接
        elif isinstance(value, ast.BinOp):
            found = _propagate_taint_through_binop(
                value, self._tainted_vars, "", 0, self.file_path, self.source_code
            )
            if found:
                new_taints = found

        # 检查 f-string
        elif isinstance(value, ast.JoinedStr):
            found = _propagate_taint_through_joinedstr(
                value, self._tainted_vars, "", 0, self.file_path, self.source_code
            )
            if found:
                new_taints = found

        # 检查变量引用
        elif isinstance(value, ast.Name):
            if value.id in self._tainted_vars:
                new_taints = [self._tainted_vars[value.id]]

        # 检查属性访问
        elif isinstance(value, ast.Attribute):
            var_name = _extract_variable_name(value)
            if var_name in self._tainted_vars:
                new_taints = [self._tainted_vars[var_name]]

        # 如果有新污点，传播到赋值目标
        if new_taints and not sanitized:
            for target in node.targets:
                target_names = self._extract_target_names(target)
                for name in target_names:
                    # 合合所有源污点的信息
                    combined_source = ", ".join(t.source for t in new_taints if t.source)
                    combined_source_line = min(t.source_line for t in new_taints if t.source_line) or _get_node_line(node)
                    combined_steps: list[TaintTraceStep] = []
                    for t in new_taints:
                        combined_steps.extend(t.trace_steps)

                    # 添加传播步骤
                    propagate_step = TaintTraceStep(
                        file=self.file_path,
                        line=_get_node_line(node),
                        col=_get_node_col(node),
                        node_type="propagation",
                        code_snippet=_get_code_snippet(self.source_code, _get_node_line(node)),
                        variable=name,
                        description=f"污点传播到变量 {name}",
                    )
                    combined_steps.append(propagate_step)

                    taint_var = TaintVariable(
                        name=name,
                        tainted=True,
                        source=combined_source,
                        source_line=combined_source_line,
                        trace_steps=combined_steps,
                    )
                    self._tainted_vars[name] = taint_var

        # 继续遍历子节点
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """处理函数调用，检查污点汇."""
        # 首先检查是否是净化器调用（在污点汇检测之前）
        sanitizer_pattern = _match_sanitizer_pattern(node, self._sanitizer_patterns)
        if sanitizer_pattern:
            sanitizer_name = sanitizer_pattern.get("name", "")
            condition = sanitizer_pattern.get("condition", "")
            
            # 检查净化器条件
            is_sanitized = False
            
            # 特殊处理 subprocess 安全调用
            if condition == "shell_false_list_args" and _is_subprocess_safe(node):
                is_sanitized = True
            
            # 特殊处理 SQL 参数化查询
            if condition == "has_params" and _is_sql_safe(node):
                is_sanitized = True
            
            # 如果满足净化条件，标记涉及的污点变量为已净化
            if is_sanitized:
                found = _contains_tainted_variable(node, self._tainted_vars)
                for taint_var in found:
                    taint_var.sanitized = True
                    taint_var.sanitizer = sanitizer_name
        
        # 检查是否是污点汇
        sink_pattern = _match_sink_pattern(node, self._sink_patterns)
        if sink_pattern:
            # 检查调用参数是否包含污点
            found = _contains_tainted_variable(node, self._tainted_vars)

            # 检查是否经过净化
            sanitized = False
            sanitizer_name = ""
            for taint_var in found:
                if taint_var.sanitized:
                    sanitized = True
                    sanitizer_name = taint_var.sanitizer
                    break

            if found and not sanitized:
                # 发现漏洞！
                vulnerability_type = sink_pattern.get("vulnerability", self.rule_config.rule_name)
                sink_name = sink_pattern.get("name", "")
                sink_desc = sink_pattern.get("description", "")

                # 构建污点追踪路径
                trace_steps: list[TaintTraceStep] = []
                for taint_var in found:
                    trace_steps.extend(taint_var.trace_steps)

                # 添加污点汇步骤
                sink_step = TaintTraceStep(
                    file=self.file_path,
                    line=_get_node_line(node),
                    col=_get_node_col(node),
                    node_type="sink",
                    code_snippet=_get_code_snippet(self.source_code, _get_node_line(node)),
                    variable=sink_name,
                    description=f"污点汇: {sink_desc}",
                )
                trace_steps.append(sink_step)

                # 创建检测结果
                finding = TaintFinding(
                    type=vulnerability_type,
                    file=self.file_path,
                    line=_get_node_line(node),
                    severity=self.rule_config.severity,
                    engine="taint",
                    confidence=self.rule_config.confidence if not sanitized else "low",
                    rule_id=self.rule_config.rule_id,
                    cwe=self.rule_config.cwe,
                    message=self.rule_config.message,
                    source=found[0].source if found else "",
                    sink=sink_name,
                    source_line=found[0].source_line if found else 0,
                    sink_line=_get_node_line(node),
                    taint_trace=trace_steps,
                    sanitized=sanitized,
                    sanitizer=sanitizer_name,
                )
                self._findings.append(finding)

        # 继续遍历子节点
        self.generic_visit(node)

    def _extract_target_names(self, target: ast.AST) -> list[str]:
        """从赋值目标提取变量名."""
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            base = _extract_variable_name(target.value)
            if base:
                return [f"{base}.{target.attr}"]
            return [target.attr]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in target.elts:
                names.extend(self._extract_target_names(elt))
            return names
        return []


class TaintEngine:
    """污点分析引擎."""

    def __init__(self) -> None:
        """初始化引擎."""
        pass

    def scan_file(self, file_path: str, rules: list[Rule]) -> list[TaintFinding]:
        """对单个文件运行污点分析.

        Parameters
        ----------
        file_path:
            要检测的 Python 文件路径.
        rules:
            污点规则列表（engine == "taint"）.

        Returns
        -------
        list[TaintFinding]
            检测到的漏洞列表.
        """
        # 只处理 Python 文件
        if not file_path.endswith(".py"):
            return []

        source = Path(file_path).read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings: list[TaintFinding] = []

        for rule in rules:
            # 从规则 pattern 中提取污点配置
            config = self._extract_taint_config(rule)
            if not config:
                continue

            # 创建函数级分析器
            analyzer = FunctionTaintAnalyzer(file_path, source, config)
            rule_findings = analyzer.analyze(tree)

            # 设置文件路径
            for f in rule_findings:
                f.file = file_path

            findings.extend(rule_findings)

        return findings

    def _extract_taint_config(self, rule: Rule) -> TaintRuleConfig | None:
        """从 Rule 对象提取污点配置."""
        pattern = rule.pattern
        if not pattern:
            return None

        # 检查是否有污点配置
        sources = pattern.get("sources", [])
        sinks = pattern.get("sinks", [])
        if not sources or not sinks:
            return None

        return TaintRuleConfig(
            sources=sources,
            sinks=sinks,
            sanitizers=pattern.get("sanitizers", []),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            cwe=rule.cwe,
            confidence=rule.confidence,
            message=rule.message,
            language=rule.language,
            enabled=rule.enabled,
        )