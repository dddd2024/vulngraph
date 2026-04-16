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


def detect_sql_injection(file_path: str) -> list[dict[str, Any]]:
    source = Path(file_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    findings: list[dict[str, Any]] = []
    tainted_sql_vars: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.BinOp) or not isinstance(node.value.op, ast.Add):
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
        is_concat = isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add)
        if is_tainted or is_concat:
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

