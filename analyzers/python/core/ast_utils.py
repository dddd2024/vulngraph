"""AST 工具函数 – 从 detector/vuln_detector.py 抽取的公共工具.

vuln_detector.py 仍保留原始实现以兼容旧代码；
新引擎（ast_rule_engine / plugin_engine）应从此模块导入.
"""

from __future__ import annotations

import ast


def qualified_name(node: ast.AST) -> str:
    """递归获取 AST 节点的完全限定名（如 ``subprocess.run``）."""
    if isinstance(node, ast.Call):
        return qualified_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = qualified_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return ""


def keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    """获取调用中指定关键字参数的 AST 节点."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def keyword_is_true(call: ast.Call, name: str) -> bool:
    """判断关键字参数是否为 ``True``."""
    value = keyword_value(call, name)
    return isinstance(value, ast.Constant) and value.value is True


def keyword_is_false(call: ast.Call, name: str) -> bool:
    """判断关键字参数是否为 ``False``."""
    value = keyword_value(call, name)
    return isinstance(value, ast.Constant) and value.value is False


def target_names(target: ast.AST) -> list[str]:
    """从赋值目标提取变量名列表."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(target_names(element))
        return names
    return []


def literal_text(node: ast.AST) -> str:
    """从 AST 节点提取字面量文本（支持 Constant、JoinedStr、BinOp、format 调用）."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        return literal_text(node.left) + literal_text(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return literal_text(node.func.value)
    return ""


def contains_dynamic_value(node: ast.AST) -> bool:
    """判断 AST 节点是否包含动态值（变量、调用、下标等）."""
    if isinstance(node, ast.FormattedValue):
        return True
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Call):
        return True
    if isinstance(node, ast.Subscript):
        return True
    if isinstance(node, ast.Attribute):
        return True
    if isinstance(node, ast.Starred):
        return True
    return any(contains_dynamic_value(child) for child in ast.iter_child_nodes(node))


def parse_ast(file_path: str) -> ast.AST:
    """解析文件为 AST."""
    from pathlib import Path

    source = Path(file_path).read_text(encoding="utf-8")
    return ast.parse(source)


def iter_calls(file_path: str) -> list[ast.Call]:
    """遍历文件中所有 ``ast.Call`` 节点."""
    return [node for node in ast.walk(parse_ast(file_path)) if isinstance(node, ast.Call)]