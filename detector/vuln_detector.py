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


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _qualified_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return ""


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _keyword_is_true(call: ast.Call, name: str) -> bool:
    value = _keyword_value(call, name)
    return isinstance(value, ast.Constant) and value.value is True


def _keyword_is_false(call: ast.Call, name: str) -> bool:
    value = _keyword_value(call, name)
    return isinstance(value, ast.Constant) and value.value is False


def _finding(
    finding_type: str,
    file_path: str,
    node: ast.AST,
    symbol: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "file": file_path,
        "line": node.lineno,
        "symbol": symbol,
        "severity": severity,
    }


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
    if isinstance(node, ast.Starred):
        return True
    return any(_contains_dynamic_value(child) for child in ast.iter_child_nodes(node))


def _parse_ast(file_path: str) -> ast.AST:
    source = Path(file_path).read_text(encoding="utf-8")
    return ast.parse(source)


def _iter_calls(file_path: str) -> list[ast.Call]:
    return [node for node in ast.walk(_parse_ast(file_path)) if isinstance(node, ast.Call)]


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


def detect_dangerous_code_execution(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in _iter_calls(file_path):
        name = _qualified_name(node)
        if name in {"eval", "exec", "compile"}:
            findings.append(
                _finding(
                    "Dangerous Code Execution",
                    file_path,
                    node,
                    name,
                    "ERROR",
                )
            )
    return findings


def detect_command_injection(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    subprocess_calls = {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
    }
    for node in _iter_calls(file_path):
        name = _qualified_name(node)
        if name in {"os.system", "os.popen"} or (
            name in subprocess_calls and _keyword_is_true(node, "shell")
        ):
            findings.append(
                _finding("Command Injection", file_path, node, name, "ERROR")
            )
    return findings


def _is_safe_yaml_loader(node: ast.AST) -> bool:
    return _qualified_name(node) in {"SafeLoader", "yaml.SafeLoader"}


def detect_unsafe_deserialization(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    always_unsafe = {
        "pickle.load",
        "pickle.loads",
        "marshal.load",
        "marshal.loads",
    }
    for node in _iter_calls(file_path):
        name = _qualified_name(node)
        is_unsafe = name in always_unsafe
        if name == "yaml.load":
            loader = _keyword_value(node, "Loader")
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            is_unsafe = loader is None or not _is_safe_yaml_loader(loader)

        if is_unsafe:
            findings.append(
                _finding("Unsafe Deserialization", file_path, node, name, "ERROR")
            )
    return findings


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_target_names(element))
        return names
    return []


def _is_non_empty_string_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(node.value)


def _looks_like_secret_name(name: str) -> bool:
    lowered = name.lower()
    secret_markers = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "private_key",
    )
    return any(marker in lowered for marker in secret_markers)


def detect_hardcoded_secret(file_path: str) -> list[dict[str, Any]]:
    tree = _parse_ast(file_path)
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        targets: list[ast.AST]
        value: ast.AST | None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue

        if value is None or not _is_non_empty_string_constant(value):
            continue
        for target in targets:
            for name in _target_names(target):
                if _looks_like_secret_name(name):
                    findings.append(
                        _finding("Hardcoded Secret", file_path, node, name, "WARNING")
                    )
    return findings


def detect_weak_crypto(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    weak_calls = {"hashlib.md5", "hashlib.sha1", "DES.new", "ARC4.new"}
    for node in _iter_calls(file_path):
        name = _qualified_name(node)
        if name in weak_calls:
            findings.append(_finding("Weak Cryptography", file_path, node, name, "WARNING"))
    return findings


def detect_debug_mode(file_path: str) -> list[dict[str, Any]]:
    tree = _parse_ast(file_path)
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _qualified_name(node)
            if name.endswith(".run") and _keyword_is_true(node, "debug"):
                findings.append(_finding("Debug Mode Enabled", file_path, node, name, "WARNING"))
        elif isinstance(node, ast.Assign):
            if not (isinstance(node.value, ast.Constant) and node.value.value is True):
                continue
            for target in node.targets:
                for name in _target_names(target):
                    if name == "DEBUG":
                        findings.append(
                            _finding("Debug Mode Enabled", file_path, node, name, "WARNING")
                        )
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.value, ast.Constant)
                and node.value.value is True
                and any(name == "DEBUG" for name in _target_names(node.target))
            ):
                findings.append(
                    _finding("Debug Mode Enabled", file_path, node, "DEBUG", "WARNING")
                )
    return findings


def detect_insecure_tls(file_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    requests_calls = {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.request",
        "requests.head",
        "requests.patch",
    }
    for node in _iter_calls(file_path):
        name = _qualified_name(node)
        if name in requests_calls and _keyword_is_false(node, "verify"):
            findings.append(
                _finding("Insecure TLS Verification", file_path, node, name, "WARNING")
            )
    return findings


def detect_all(repo_root: str = "repo") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for file_path in scan_repo(repo_root, exts=(".py",)):
        findings.extend(detect_sql_injection(file_path))
        findings.extend(detect_path_traversal(file_path))
        findings.extend(detect_privilege_escalation(file_path))
        findings.extend(detect_dangerous_code_execution(file_path))
        findings.extend(detect_command_injection(file_path))
        findings.extend(detect_unsafe_deserialization(file_path))
        findings.extend(detect_hardcoded_secret(file_path))
        findings.extend(detect_weak_crypto(file_path))
        findings.extend(detect_debug_mode(file_path))
        findings.extend(detect_insecure_tls(file_path))
    return findings

