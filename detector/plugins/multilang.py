"""多语言检测插件 – 支持 JavaScript/TypeScript/Java/C/C++ 的漏洞检测."""

from __future__ import annotations

from pathlib import Path
from typing import Any

# 尝试导入 Tree-sitter 多语言检测器
try:
    from detector.tree_sitter_detectors import detect_javascript_vulnerabilities
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
    detect_javascript_vulnerabilities = None

# 尝试导入 Java 检测器
try:
    from detector.java_detector import detect_java_vulnerabilities
    HAS_JAVA_DETECTOR = True
except ImportError:
    HAS_JAVA_DETECTOR = False
    detect_java_vulnerabilities = None

# 尝试导入 C/C++ 检测器
try:
    from detector.c_detector import detect_c_vulnerabilities
    HAS_C_DETECTOR = True
except ImportError:
    HAS_C_DETECTOR = False
    detect_c_vulnerabilities = None

# 尝试导入语言自动检测
try:
    from parser.language_detector import detect_language as auto_detect_language
    HAS_LANGUAGE_DETECTOR = True
except ImportError:
    HAS_LANGUAGE_DETECTOR = False
    auto_detect_language = None


def _map_vuln_type_to_cwe(vuln_type: str) -> str:
    """将漏洞类型映射到 CWE 编号."""
    cwe_map = {
        "SQL Injection": "CWE-89",
        "Path Traversal": "CWE-22",
        "Command Injection": "CWE-78",
        "Cross-Site Scripting (XSS)": "CWE-79",
        "Insecure Deserialization": "CWE-502",
        "XML External Entity (XXE)": "CWE-611",
        "LDAP Injection": "CWE-90",
        "Buffer Overflow": "CWE-120",
        "Format String Vulnerability": "CWE-134",
        "Memory Leak": "CWE-401",
        "Code Injection / Eval Usage": "CWE-94",
        "Log Injection": "CWE-117",
        "Insecure Random Number": "CWE-338",
        "Race Condition (TOCTOU)": "CWE-362",
        "Null Pointer Dereference": "CWE-476",
        "Integer Overflow": "CWE-190",
        "SSRF": "CWE-918",
    }
    return cwe_map.get(vuln_type, "CWE-Other")


def _detect_js_ts(repo_root: Path, language: str) -> list[dict[str, Any]]:
    """检测 JavaScript/TypeScript 漏洞."""
    findings: list[dict[str, Any]] = []
    if not HAS_TREE_SITTER or detect_javascript_vulnerabilities is None:
        return findings

    extensions = [".js", ".jsx"] if language == "javascript" else [".ts", ".tsx"]
    code_files = [p for p in repo_root.rglob("*") if p.suffix in extensions and p.is_file()]

    for code_file in code_files:
        try:
            vulns = detect_javascript_vulnerabilities(str(code_file))
            for v in vulns:
                findings.append({
                    "type": v["type"],
                    "file": str(code_file.relative_to(repo_root)).replace("\\", "/"),
                    "line": v["line"],
                    "symbol": v.get("symbol", ""),
                    "severity": v["severity"],
                    "engine": "tree-sitter",
                    "confidence": v.get("confidence", "medium"),
                    "cwe": _map_vuln_type_to_cwe(v["type"]),
                    "detector": f"{language}_detector",
                })
        except Exception:
            continue
    return findings


def _detect_java(repo_root: Path) -> list[dict[str, Any]]:
    """检测 Java 漏洞."""
    findings: list[dict[str, Any]] = []
    if not HAS_JAVA_DETECTOR or detect_java_vulnerabilities is None:
        return findings

    java_files = [p for p in repo_root.rglob("*.java") if p.is_file()]
    for java_file in java_files:
        try:
            vulns = detect_java_vulnerabilities(str(java_file))
            for v in vulns:
                findings.append({
                    "type": v["type"],
                    "file": str(java_file.relative_to(repo_root)).replace("\\", "/"),
                    "line": v["line"],
                    "symbol": v.get("symbol", ""),
                    "severity": v["severity"],
                    "engine": "tree-sitter",
                    "confidence": v.get("confidence", "medium"),
                    "cwe": _map_vuln_type_to_cwe(v["type"]),
                    "detector": "java_detector",
                })
        except Exception:
            continue
    return findings


def _detect_c_cpp(repo_root: Path, language: str) -> list[dict[str, Any]]:
    """检测 C/C++ 漏洞."""
    findings: list[dict[str, Any]] = []
    if not HAS_C_DETECTOR or detect_c_vulnerabilities is None:
        return findings

    if language == "c":
        extensions = [".c", ".h"]
    else:
        extensions = [".cpp", ".cc", ".cxx", ".hpp"]

    c_files = [p for p in repo_root.rglob("*") if p.suffix in extensions and p.is_file()]
    for c_file in c_files:
        try:
            vulns = detect_c_vulnerabilities(str(c_file))
            for v in vulns:
                findings.append({
                    "type": v["type"],
                    "file": str(c_file.relative_to(repo_root)).replace("\\", "/"),
                    "line": v["line"],
                    "symbol": v.get("symbol", ""),
                    "severity": v["severity"],
                    "engine": "tree-sitter",
                    "confidence": v.get("confidence", "medium"),
                    "cwe": _map_vuln_type_to_cwe(v["type"]),
                    "detector": f"{language}_detector",
                })
        except Exception:
            continue
    return findings


def scan_repository(repo_root: str | Path, language: str | None = None) -> list[dict[str, Any]]:
    """扫描仓库中的多语言漏洞.

    Parameters
    ----------
    repo_root: 仓库根目录路径
    language: 指定语言，None 则自动检测

    Returns
    -------
    list[dict[str, Any]]: 漏洞发现列表
    """
    repo_root = Path(repo_root)
    findings: list[dict[str, Any]] = []

    # 自动检测语言
    if language is None and HAS_LANGUAGE_DETECTOR and auto_detect_language is not None:
        try:
            language = auto_detect_language(str(repo_root))
        except Exception:
            language = "python"
    elif language is None:
        language = "python"

    # 根据语言调用对应检测器
    if language in ("javascript", "typescript"):
        findings.extend(_detect_js_ts(repo_root, language))
    elif language == "java":
        findings.extend(_detect_java(repo_root))
    elif language in ("c", "cpp"):
        findings.extend(_detect_c_cpp(repo_root, language))

    return findings


def run(file_path: str) -> list[dict[str, Any]]:
    """插件入口函数 - 对单个文件运行检测（用于兼容性）.

    注意：多语言检测更适合在仓库级别运行，
    此函数主要用于插件接口兼容性。
    """
    # 根据文件扩展名确定语言
    path = Path(file_path)
    ext = path.suffix.lower()

    lang_map = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
    }

    language = lang_map.get(ext)
    if language is None:
        return []

    # 在文件所在目录运行检测
    return scan_repository(path.parent, language)


def get_supported_languages() -> list[str]:
    """获取支持的语言列表."""
    languages = ["python"]  # Python 始终支持

    if HAS_TREE_SITTER:
        languages.extend(["javascript", "typescript"])
    if HAS_JAVA_DETECTOR:
        languages.append("java")
    if HAS_C_DETECTOR:
        languages.extend(["c", "cpp"])

    return languages


def is_language_supported(language: str) -> bool:
    """检查指定语言是否支持."""
    return language in get_supported_languages()
