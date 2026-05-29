"""污点分析引擎 – 基于 AST 的污点传播追踪检测.

修复版本特性：
- 单文件、函数内污点传播
- 支持赋值传播、字符串拼接、f-string、format、函数调用返回值保守传播
- 支持 arg_index 指定 sink 危险参数位置
- 支持 propagators（如 os.path.join）传播但不报漏洞
- 修复 sanitizer 状态污染：参数化 SQL 只抑制当前调用，secure_filename 只净化返回值
- 检测 SQL Injection、Path Traversal、Command Injection 三类漏洞
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from detector.core.ast_utils import qualified_name, keyword_is_false, keyword_is_true, keyword_value
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
    """检查节点是否匹配污点源模式.

    只支持精确匹配和明确后缀匹配，不支持宽泛匹配。
    """
    call_name = qualified_name(node)
    for pattern in source_patterns:
        pattern_name = pattern.get("name", "")
        # 精确匹配或后缀匹配（如 request.args.get 匹配 .args.get）
        if call_name == pattern_name or call_name.endswith("." + pattern_name):
            return pattern
    return None


def _match_sink_pattern(node: ast.Call, sink_patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    """检查节点是否匹配污点汇模式.

    支持精确匹配、后缀匹配，以及处理链式调用和变量名模式。
    优先匹配更具体的模式（带通配符的 > 简单后缀匹配）。
    """
    call_name = qualified_name(node)
    best_match = None
    best_specificity = 0  # 特异性分数，越高越优先
    
    for pattern in sink_patterns:
        pattern_name = pattern.get("name", "")
        is_wildcard = pattern_name.startswith("*.")
        
        # 通配符模式：*.method 匹配 var.method
        if is_wildcard:
            suffix = pattern_name[2:]  # 去掉 *. 前缀
            if call_name.endswith("." + suffix):
                # 通配符模式特异性 = 方法名长度 + 10（优先）
                specificity = len(suffix) + 10
                if specificity > best_specificity:
                    best_specificity = specificity
                    best_match = pattern
            continue
        
        # 精确匹配
        if call_name == pattern_name:
            specificity = len(pattern_name) + 5
            if specificity > best_specificity:
                best_specificity = specificity
                best_match = pattern
            continue
        
        # 后缀匹配：完整路径匹配
        if call_name.endswith("." + pattern_name):
            # 检查后缀前面是否有更多内容（更具体）
            prefix = call_name[:-len(pattern_name) - 1]
            specificity = len(pattern_name)
            if prefix:  # 有前缀，更具体
                specificity += len(prefix) * 0.5
            if specificity > best_specificity:
                best_specificity = specificity
                best_match = pattern
            continue
        
        # 处理链式调用：Path(path).read_text 匹配 Path.read_text
        if "(" in call_name:
            simple_name = call_name.replace("(", "").replace(")", "").replace(" ", "")
            if simple_name == pattern_name or simple_name.endswith("." + pattern_name):
                specificity = len(pattern_name)
                if specificity > best_specificity:
                    best_specificity = specificity
                    best_match = pattern
                continue
    
    return best_match


def _match_propagator_pattern(node: ast.Call, propagator_patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    """检查节点是否匹配传播器模式."""
    call_name = qualified_name(node)
    for pattern in propagator_patterns:
        pattern_name = pattern.get("name", "")
        if call_name == pattern_name or call_name.endswith("." + pattern_name):
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
    """检查 subprocess 调用是否安全（shell=False 或默认且使用列表参数）.
    
    安全的 subprocess 调用：
    - shell=False 且使用列表参数
    - 没有 shell 参数（默认 False）且使用列表参数
    """
    call_name = qualified_name(node)
    if not call_name.startswith("subprocess."):
        return False

    # 检查 shell 参数
    shell_value = keyword_value(node, "shell")
    if shell_value is not None:
        # 显式设置了 shell 参数
        if not (isinstance(shell_value, ast.Constant) and shell_value.value is False):
            # shell=True 或其他值，不安全
            return False
    # 如果没有 shell 参数，默认为 False，继续检查

    # 检查第一个参数是否为列表
    if node.args:
        first_arg = node.args[0]
        if isinstance(first_arg, (ast.List, ast.Tuple)):
            return True

    return False


def _is_subprocess_shell_true(node: ast.Call) -> bool:
    """检查 subprocess 调用是否显式设置了 shell=True."""
    call_name = qualified_name(node)
    if not call_name.startswith("subprocess."):
        return False
    
    shell_value = keyword_value(node, "shell")
    if shell_value is not None:
        return isinstance(shell_value, ast.Constant) and shell_value.value is True
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


def _contains_tainted_variable_in_arg(
    node: ast.Call,
    arg_index: int,
    tainted_vars: dict[str, TaintVariable]
) -> list[TaintVariable]:
    """检查指定位置的参数是否包含污点变量.

    arg_index=-1 表示检查接收者（self），即调用该方法的对象。
    """
    if arg_index == -1:
        # 检查接收者（self）
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            return _contains_tainted_variable(receiver, tainted_vars)
        return []
    
    if arg_index < len(node.args):
        target_arg = node.args[arg_index]
        return _contains_tainted_variable(target_arg, tainted_vars)
    return []


def _is_arg_sanitized(
    node: ast.Call,
    arg_index: int,
    tainted_vars: dict[str, TaintVariable],
    sanitizer_patterns: list[dict[str, Any]]
) -> tuple[bool, str]:
    """检查指定位置的参数是否被 sanitizer 包裹.

    用于检测如 os.system("ls " + shlex.quote(name)) 这种变量被 sanitizer 包裹的情况。
    返回 (is_sanitized, sanitizer_name)。
    """
    def _check_sanitizer_in_node(n: ast.AST) -> tuple[bool, str]:
        """递归检查节点中是否有 sanitizer 包裹污点变量."""
        if isinstance(n, ast.Call):
            # 检查是否是 sanitizer
            sanitizer_pattern = _match_sanitizer_pattern(n, sanitizer_patterns)
            if sanitizer_pattern:
                sanitizer_name = sanitizer_pattern.get("name", "")
                # 检查 sanitizer 的参数是否包含污点变量
                found = _contains_tainted_variable(n, tainted_vars)
                if found:
                    return (True, sanitizer_name)
                return (False, "")
            
            # 递归检查参数
            for arg in n.args:
                result = _check_sanitizer_in_node(arg)
                if result[0]:
                    return result
            for kw in n.keywords:
                result = _check_sanitizer_in_node(kw.value)
                if result[0]:
                    return result
        
        elif isinstance(n, ast.BinOp):
            # 检查字符串拼接
            left_result = _check_sanitizer_in_node(n.left)
            if left_result[0]:
                return left_result
            return _check_sanitizer_in_node(n.right)
        
        return (False, "")
    
    if arg_index == -1:
        # 检查接收者
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            return _check_sanitizer_in_node(receiver)
        return (False, "")
    
    if arg_index < len(node.args):
        target_arg = node.args[arg_index]
        return _check_sanitizer_in_node(target_arg)
    return (False, "")


def _find_source_call_in_arg(
    node: ast.Call,
    arg_index: int,
    source_patterns: list[dict[str, Any]],
    sanitizer_patterns: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, bool, str]:
    """查找指定位置的参数中的 source call，返回 (source_pattern, is_sanitized, sanitizer_name).

    用于检测如 os.system(request.args.get("cmd")) 这种直接传递 source 到 sink 的情况。
    同时检测 source call 是否被 sanitizer 包裹（如 secure_filename(request.args.get("path"))）。
    """
    result: tuple[dict[str, Any] | None, bool, str] = (None, False, "")
    
    def _find_source_and_sanitizer_in_node(n: ast.AST, in_sanitizer: bool = False, sanitizer_name: str = "") -> tuple[dict[str, Any] | None, bool, str]:
        """递归查找节点中的 source call 和 sanitizer."""
        if isinstance(n, ast.Call):
            # 先检查是否是 sanitizer
            sanitizer_pattern = _match_sanitizer_pattern(n, sanitizer_patterns)
            if sanitizer_pattern and not in_sanitizer:
                # 这是一个 sanitizer 调用，检查其参数中是否有 source
                sanitizer_name = sanitizer_pattern.get("name", "")
                for arg in n.args:
                    inner_result = _find_source_and_sanitizer_in_node(arg, True, sanitizer_name)
                    if inner_result[0]:
                        return inner_result
                for kw in n.keywords:
                    inner_result = _find_source_and_sanitizer_in_node(kw.value, True, sanitizer_name)
                    if inner_result[0]:
                        return inner_result
                return (None, False, "")
            
            # 检查是否是 source
            source_pattern = _match_source_pattern(n, source_patterns)
            if source_pattern:
                return (source_pattern, in_sanitizer, sanitizer_name)
            
            # 递归检查参数
            for arg in n.args:
                inner_result = _find_source_and_sanitizer_in_node(arg, in_sanitizer, sanitizer_name)
                if inner_result[0]:
                    return inner_result
            for kw in n.keywords:
                inner_result = _find_source_and_sanitizer_in_node(kw.value, in_sanitizer, sanitizer_name)
                if inner_result[0]:
                    return inner_result
        
        elif isinstance(n, ast.BinOp):
            left_result = _find_source_and_sanitizer_in_node(n.left, in_sanitizer, sanitizer_name)
            if left_result[0]:
                return left_result
            return _find_source_and_sanitizer_in_node(n.right, in_sanitizer, sanitizer_name)
        
        elif isinstance(n, ast.JoinedStr):
            for value in n.values:
                if isinstance(value, ast.FormattedValue):
                    inner_result = _find_source_and_sanitizer_in_node(value.value, in_sanitizer, sanitizer_name)
                    if inner_result[0]:
                        return inner_result
        
        return (None, False, "")
    
    if arg_index == -1:
        # 检查接收者
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            return _find_source_and_sanitizer_in_node(receiver)
        return (None, False, "")
    
    if arg_index < len(node.args):
        target_arg = node.args[arg_index]
        return _find_source_and_sanitizer_in_node(target_arg)
    return (None, False, "")


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
        self._propagator_patterns = rule_config.propagators

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
                # 检查是否是净化器调用
                sanitizer_pattern = _match_sanitizer_pattern(value, self._sanitizer_patterns)
                if sanitizer_pattern:
                    sanitizer_name = sanitizer_pattern.get("name", "")
                    condition = sanitizer_pattern.get("condition", "")
                    
                    # 检查净化器参数是否包含污点
                    found = _contains_tainted_variable(value, self._tainted_vars)
                    
                    # 一般净化器（如 secure_filename, shlex.quote）
                    # 净化返回值，原变量保持不变
                    if found and (not condition or condition == ""):
                        sanitized = True
                        new_taints = []  # 净化后的值视为安全
                        # 创建净化后的变量（标记为已净化）
                        for target in node.targets:
                            target_names = self._extract_target_names(target)
                            for name in target_names:
                                # 复制污点信息但标记为已净化
                                combined_steps: list[TaintTraceStep] = []
                                for t in found:
                                    combined_steps.extend(t.trace_steps)
                                
                                sanitize_step = TaintTraceStep(
                                    file=self.file_path,
                                    line=_get_node_line(node),
                                    col=_get_node_col(node),
                                    node_type="sanitizer",
                                    code_snippet=_get_code_snippet(self.source_code, _get_node_line(node)),
                                    variable=name,
                                    description=f"净化器: {sanitizer_name}",
                                )
                                combined_steps.append(sanitize_step)
                                
                                taint_var = TaintVariable(
                                    name=name,
                                    tainted=True,  # 仍然标记为污点，但 sanitized=True
                                    source=found[0].source if found else "",
                                    source_line=found[0].source_line if found else 0,
                                    sanitized=True,
                                    sanitizer=sanitizer_name,
                                    trace_steps=combined_steps,
                                )
                                self._tainted_vars[name] = taint_var
                
                # 检查是否是传播器（如 os.path.join）
                elif not sanitized:
                    propagator_pattern = _match_propagator_pattern(value, self._propagator_patterns)
                    if propagator_pattern:
                        # 传播器：传播污点但不报漏洞
                        # 支持 arg_indices: all 或 arg_indices: [0, 1, 2]
                        arg_indices = propagator_pattern.get("arg_indices")
                        if arg_indices == "all":
                            # 检查所有参数
                            found = []
                            for i in range(len(value.args)):
                                found.extend(_contains_tainted_variable_in_arg(value, i, self._tainted_vars))
                        elif isinstance(arg_indices, list):
                            # 检查指定索引列表
                            found = []
                            for idx in arg_indices:
                                found.extend(_contains_tainted_variable_in_arg(value, idx, self._tainted_vars))
                        else:
                            # 使用单个 arg_index（向后兼容）
                            arg_index = propagator_pattern.get("arg_index", 0)
                            found = _contains_tainted_variable_in_arg(value, arg_index, self._tainted_vars)
                        if found:
                            new_taints = found
                    else:
                        # 普通函数调用：保守传播
                        found = _contains_tainted_variable(value, self._tainted_vars)
                        if found:
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
                    # 合并所有源污点的信息（去重）
                    unique_sources = list(set(t.source for t in new_taints if t.source))
                    combined_source = ", ".join(unique_sources)
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
        # 检查是否是污点汇
        sink_pattern = _match_sink_pattern(node, self._sink_patterns)
        if sink_pattern:
            # 获取 sink 的危险参数位置
            arg_index = sink_pattern.get("arg_index", 0)
            
            # 只检查指定位置的参数
            found = _contains_tainted_variable_in_arg(node, arg_index, self._tainted_vars)
            
            # 检查是否是 inline source → sink（如 os.system(request.args.get("cmd"))）
            # 使用新的 _find_source_call_in_arg 函数
            inline_source_pattern, inline_sanitized, inline_sanitizer_name = _find_source_call_in_arg(
                node, arg_index, self._source_patterns, self._sanitizer_patterns
            )
            is_inline_source = inline_source_pattern is not None
            inline_source_name = inline_source_pattern.get("name", "") if inline_source_pattern else ""
            
            # 如果 inline source 被 sanitizer 包裹，则不报漏洞或降低置信度
            if is_inline_source and inline_sanitized:
                # inline source 已被净化，不报漏洞
                is_inline_source = False

            # 检查是否是 SQL 参数化查询（特殊处理：只抑制当前调用）
            call_name = qualified_name(node)
            is_sql_execute = any(call_name.endswith(s) for s in ["execute", "executemany"])
            
            if is_sql_execute and len(node.args) >= 2:
                # 参数化查询：第二个参数存在，当前调用安全
                found = []
                is_inline_source = False
            
            # 检查是否是安全的 subprocess 调用（shell=False 且列表参数）
            is_subprocess = call_name.startswith("subprocess.")
            if is_subprocess:
                if _is_subprocess_safe(node):
                    # 安全的 subprocess 调用（shell=False 或默认 + 列表参数），不报漏洞
                    found = []
                    is_inline_source = False
                elif not _is_subprocess_shell_true(node):
                    # 没有显式 shell=True，但也不是安全调用（如字符串参数），不报漏洞
                    # 只有 shell=True 且参数 tainted 时才报
                    found = []
                    is_inline_source = False
            
            # 检查是否经过净化
            sanitized = False
            sanitizer_name = ""
            for taint_var in found:
                if taint_var.sanitized:
                    sanitized = True
                    sanitizer_name = taint_var.sanitizer
                    break
            
            # 检查参数是否被 sanitizer 包裹（如 shlex.quote(name)）
            if found and not sanitized:
                arg_sanitized, arg_sanitizer_name = _is_arg_sanitized(
                    node, arg_index, self._tainted_vars, self._sanitizer_patterns
                )
                if arg_sanitized:
                    sanitized = True
                    sanitizer_name = arg_sanitizer_name

            if (found and not sanitized) or is_inline_source:
                # 发现漏洞！
                vulnerability_type = sink_pattern.get("vulnerability", self.rule_config.rule_name)
                sink_name = sink_pattern.get("name", "")
                sink_desc = sink_pattern.get("description", "")

                # 构建污点追踪路径
                trace_steps: list[TaintTraceStep] = []
                if found:
                    for taint_var in found:
                        trace_steps.extend(taint_var.trace_steps)
                elif is_inline_source:
                    # 创建 inline source 的 trace step
                    source_step = TaintTraceStep(
                        file=self.file_path,
                        line=_get_node_line(node),
                        col=_get_node_col(node),
                        node_type="source",
                        code_snippet=_get_code_snippet(self.source_code, _get_node_line(node)),
                        variable=inline_source_name,
                        description=f"Inline 污点源: {inline_source_name}",
                    )
                    trace_steps.append(source_step)

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
                    source=found[0].source if found else inline_source_name,
                    sink=sink_name,
                    source_line=found[0].source_line if found else _get_node_line(node),
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
            propagators=pattern.get("propagators", []),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            cwe=rule.cwe,
            confidence=rule.confidence,
            message=rule.message,
            language=rule.language,
            enabled=rule.enabled,
        )