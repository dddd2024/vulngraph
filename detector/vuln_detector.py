import ast
from pathlib import Path
from typing import Any

from parser.ast_parser import parse_file
from parser.repo_scanner import scan_repo


def _call_attr_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return "<unknown>"


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        return _literal_text(node.left) + _literal_text(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _literal_text(node.func.value)
    return ""


def _looks_like_sql(text: str) -> bool:
    normalized = text.upper()
    return any(
        keyword in normalized
        for keyword in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", " WHERE ")
    )


def _contains_dynamic_value(node: ast.AST) -> bool:
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
    return any(_contains_dynamic_value(child) for child in ast.iter_child_nodes(node))


def _is_unsafe_sql_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return _looks_like_sql(_literal_text(node)) and any(
            isinstance(value, ast.FormattedValue) for value in node.values
        )

    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            text = _literal_text(node)
            return _looks_like_sql(text) and _contains_dynamic_value(node)
        if isinstance(node.op, ast.Mod):
            return _looks_like_sql(_literal_text(node.left)) and _contains_dynamic_value(
                node.right
            )

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return _looks_like_sql(_literal_text(node.func.value)) and (
                bool(node.args) or bool(node.keywords)
            )

    return False


def detect_sql_injection(file_path: str) -> list[dict[str, Any]]:
    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    findings: list[dict[str, Any]] = []
    tainted_sql_vars: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not _is_unsafe_sql_expr(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                tainted_sql_vars.add(target.id)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_attr_name(node) != "execute" or not node.args:
            continue
        first_arg = node.args[0]
        is_tainted = isinstance(first_arg, ast.Name) and first_arg.id in tainted_sql_vars
        is_unsafe_inline = _is_unsafe_sql_expr(first_arg)
        if is_tainted or is_unsafe_inline:
            findings.append(
                {
                    "type": "SQL Injection",
                    "file": file_path,
                    "line": node.lineno,
                    "symbol": "search_user",
                    "severity": "ERROR",
                }
            )
    return findings


def detect_path_traversal(file_path: str) -> list[dict[str, Any]]:
    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_attr_name(node) != "open" or not node.args:
            continue
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Name):
            findings.append(
                {
                    "type": "Path Traversal",
                    "file": file_path,
                    "line": node.lineno,
                    "symbol": "read_file",
                    "severity": "ERROR",
                }
            )
    return findings


def detect_privilege_escalation(file_path: str) -> list[dict[str, Any]]:
    data = parse_file(file_path)
    findings: list[dict[str, Any]] = []
    for route in data.get("routes", []):
        path = route["path"]
        decorators = set(route.get("decorators", []))
        has_auth = any(d in decorators for d in ("login_required", "admin_required"))
        if "/admin" in path and not has_auth:
            findings.append(
                {
                    "type": "Privilege Escalation",
                    "file": file_path,
                    "line": route["line"],
                    "symbol": route["function"],
                    "severity": "ERROR",
                }
            )
    return findings


def detect_all(repo_root: str = "repo") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for file_path in scan_repo(repo_root, exts=(".py",)):
        findings.extend(detect_sql_injection(file_path))
        findings.extend(detect_path_traversal(file_path))
        findings.extend(detect_privilege_escalation(file_path))
    return findings

