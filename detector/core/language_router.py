"""LanguageRouter – 多语言漏洞检测路由器.

根据文件语言自动选择合适的检测器：
- Python  → DetectorRunner（AST + Plugin + Regex 三引擎）
- JavaScript / TypeScript → tree_sitter_detectors（Tree-sitter）或 regex 回退
- Java  → java_detector（Tree-sitter）或 regex 回退
- C / C++ → c_detector（Tree-sitter）或 regex 回退
- 其他语言 → 跳过，不中断扫描

每个 finding 自动补充 ``language`` 字段。
当 tree-sitter 不可用时，自动回退到基于正则的检测器。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from parser.language_detector import detect_language

logger = logging.getLogger(__name__)

# 检测 tree-sitter 是否可用
_TREE_SITTER_AVAILABLE = False
try:
    from tree_sitter import Language, Parser  # noqa: F401
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False

# 语言显示名称映射
LANGUAGE_DISPLAY = {
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
    "c": "C",
    "cpp": "C/C++",
    "go": "Go",
    "php": "PHP",
    "rust": "Rust",
}


class LanguageRouter:
    """多语言漏洞检测路由器.

    用法::

        router = LanguageRouter()
        findings = router.scan_file("path/to/file.py")
    """

    def __init__(self) -> None:
        self._py_runner = None
        self._js_detector = None
        self._c_detector = None
        self._java_detector = None

    # ---- 延迟加载检测器 ----

    def _get_py_runner(self):
        if self._py_runner is None:
            from detector.core.runner import DetectorRunner
            self._py_runner = DetectorRunner()
        return self._py_runner

    def _get_js_detector(self):
        if self._js_detector is None:
            from detector.tree_sitter_detectors import get_detector as get_js_detector
            self._js_detector = get_js_detector()
        return self._js_detector

    def _get_java_detector(self):
        if self._java_detector is None:
            from detector.java_detector import get_detector as get_java_detector
            self._java_detector = get_java_detector()
        return self._java_detector

    def _get_c_detector(self):
        if self._c_detector is None:
            from detector.c_detector import get_detector as get_c_detector
            self._c_detector = get_c_detector()
        return self._c_detector

    # ---- 核心方法 ----

    def detect_language(self, file_path: str) -> str:
        """检测文件语言.

        Args:
            file_path: 文件路径

        Returns:
            语言标识符（如 "python", "javascript", "java" 等）
        """
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            filename = Path(file_path).name
            return detect_language(source, filename)
        except Exception:
            # 回退到扩展名检测
            ext = Path(file_path).suffix.lower()
            ext_map = {
                ".py": "python", ".js": "javascript", ".jsx": "javascript",
                ".ts": "typescript", ".tsx": "typescript", ".java": "java",
                ".go": "go", ".php": "php", ".c": "c", ".h": "c",
                ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
                ".rs": "rust",
            }
            return ext_map.get(ext, "unknown")

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        """对单个文件运行对应语言的检测器，返回 finding 列表.

        每个 finding 自动补充 ``language`` 字段。
        如果文件语言不被支持，返回空列表（不抛异常）。

        Args:
            file_path: 文件路径

        Returns:
            漏洞列表（字典格式），每个包含 language 字段
        """
        language = self.detect_language(file_path)
        findings: list[dict[str, Any]] = []

        try:
            if language == "python":
                findings = self._scan_python(file_path)
            elif language in ("javascript", "typescript"):
                findings = self._scan_javascript(file_path)
            elif language == "java":
                findings = self._scan_java(file_path)
            elif language in ("c", "cpp"):
                findings = self._scan_c_cpp(file_path)
            else:
                logger.debug("跳过不支持的文件语言: %s (%s)", language, file_path)
                return []
        except Exception as exc:
            logger.warning("文件 %s (%s) 检测失败: %s", file_path, language, exc)
            raise  # 让调用方记录到 skipped_details

        # 为每个 finding 补充 language 字段
        lang_display = LANGUAGE_DISPLAY.get(language, language)
        for f in findings:
            f["language"] = lang_display

        return findings

    # ---- 各语言扫描方法 ----

    def _scan_python(self, file_path: str) -> list[dict[str, Any]]:
        """Python 文件：使用 DetectorRunner（AST + Plugin + Regex）."""
        runner = self._get_py_runner()
        return runner.scan_file(file_path)

    def _scan_javascript(self, file_path: str) -> list[dict[str, Any]]:
        """JavaScript / TypeScript 文件：使用 tree_sitter_detectors 或 regex 回退."""
        if _TREE_SITTER_AVAILABLE:
            from detector.tree_sitter_detectors import detect_javascript_vulnerabilities
            vulns = detect_javascript_vulnerabilities(file_path)
            results = []
            for v in vulns:
                finding = dict(v)
                finding.setdefault("engine", "tree-sitter")
                finding.setdefault("confidence", "medium")
                results.append(finding)
            return results
        else:
            return _regex_scan_javascript(file_path)

    def _scan_java(self, file_path: str) -> list[dict[str, Any]]:
        """Java 文件：使用 java_detector 或 regex 回退."""
        if _TREE_SITTER_AVAILABLE:
            from detector.java_detector import detect_java_vulnerabilities
            vulns = detect_java_vulnerabilities(file_path)
            results = []
            for v in vulns:
                finding = dict(v)
                finding.setdefault("engine", "tree-sitter")
                finding.setdefault("confidence", "medium")
                results.append(finding)
            return results
        else:
            return _regex_scan_java(file_path)

    def _scan_c_cpp(self, file_path: str) -> list[dict[str, Any]]:
        """C/C++ 文件：使用 c_detector 或 regex 回退."""
        if _TREE_SITTER_AVAILABLE:
            from detector.c_detector import detect_c_vulnerabilities
            vulns = detect_c_vulnerabilities(file_path)
            results = []
            for v in vulns:
                finding = dict(v)
                finding.setdefault("engine", "tree-sitter")
                finding.setdefault("confidence", "medium")
                results.append(finding)
            return results
        else:
            return _regex_scan_c_cpp(file_path)


# =========================================================================
# 基于 Regex 的回退检测器（当 tree-sitter 不可用时使用）
# =========================================================================

def _read_source(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8", errors="ignore")


def _line_of(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _regex_scan_javascript(file_path: str) -> list[dict[str, Any]]:
    """基于正则的 JavaScript/TypeScript 漏洞检测（tree-sitter 不可用时的回退）."""
    source = _read_source(file_path)
    findings: list[dict[str, Any]] = []

    # XSS: innerHTML / outerHTML 赋值
    for m in re.finditer(r'\.\s*(innerHTML|outerHTML)\s*=', source):
        findings.append({
            "type": "Cross-Site Scripting (XSS)",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "medium",
            "engine": "regex",
            "symbol": m.group(1),
            "detail": f"Potential XSS: {m.group(1)} assignment with unsanitized content",
        })

    # Eval: eval() / setTimeout() / setInterval() with string argument
    for m in re.finditer(r'\b(eval|Function)\s*\(', source):
        findings.append({
            "type": "Code Injection / Eval Usage",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "WARNING",
            "confidence": "medium",
            "engine": "regex",
            "symbol": m.group(1),
            "detail": f"Dangerous dynamic code execution: {m.group(1)}()",
        })

    # Command Injection: exec / execSync / spawn
    for m in re.finditer(r'\b(exec|execSync|execFileSync|spawn|spawnSync)\s*\(', source):
        findings.append({
            "type": "Command Injection",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "medium",
            "engine": "regex",
            "symbol": m.group(1),
            "detail": f"Potential command injection: {m.group(1)}()",
        })

    # SQL Injection: query with string concatenation
    for m in re.finditer(r'\.(query|execute|raw|sql)\s*\(', source):
        # 检查附近是否有字符串拼接
        ctx = source[max(0, m.start() - 100):m.end() + 100]
        if '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx):
            findings.append({
                "type": "SQL Injection",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "medium",
                "engine": "regex",
                "symbol": m.group(1),
                "detail": f"Potential SQL injection: {m.group(1)}() with string concatenation",
            })

    return findings


def _regex_scan_java(file_path: str) -> list[dict[str, Any]]:
    """基于正则的 Java 漏洞检测（tree-sitter 不可用时的回退）."""
    source = _read_source(file_path)
    findings: list[dict[str, Any]] = []

    # SQL Injection: Statement.executeQuery with string concat
    for m in re.finditer(r'(executeQuery|executeUpdate|execute)\s*\(', source):
        ctx = source[max(0, m.start() - 200):m.end() + 50]
        if '+' in ctx and any(kw in ctx.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
            findings.append({
                "type": "SQL Injection",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "high",
                "engine": "regex",
                "symbol": m.group(1),
                "detail": f"SQL 查询使用字符串拼接，存在 SQL 注入风险: {m.group(1)}()",
            })

    # Command Injection: Runtime.exec / ProcessBuilder
    for m in re.finditer(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', source):
        findings.append({
            "type": "Command Injection",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "high",
            "engine": "regex",
            "symbol": "Runtime.exec",
            "detail": "命令执行函数使用了不可信输入，存在命令注入风险: Runtime.exec",
        })

    # Command Injection: rt.exec() after Runtime.getRuntime()
    for m in re.finditer(r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)', source):
        # 检查后续 5 行是否有 .exec( 调用
        ctx = source[m.start():m.end() + 300]
        if re.search(r'\.\s*exec\s*\(', ctx):
            findings.append({
                "type": "Command Injection",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "high",
                "engine": "regex",
                "symbol": "Runtime.exec",
                "detail": "命令执行函数使用了不可信输入，存在命令注入风险: Runtime.exec",
            })

    for m in re.finditer(r'ProcessBuilder\s*\(', source):
        findings.append({
            "type": "Command Injection",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "medium",
            "engine": "regex",
            "symbol": "ProcessBuilder",
            "detail": "ProcessBuilder 使用了不可信输入，存在命令注入风险",
        })

    # Path Traversal: new File(user input)
    for m in re.finditer(r'new\s+File\s*\(', source):
        ctx = source[max(0, m.start() - 50):m.end() + 100]
        if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam"]):
            findings.append({
                "type": "Path Traversal",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "high",
                "engine": "regex",
                "symbol": "File",
                "detail": "文件操作使用了用户可控的路径参数，存在路径穿越风险: File",
            })

    # XXE: DocumentBuilderFactory without secure config
    for m in re.finditer(r'DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)', source):
        ctx = source[m.start():m.end() + 500]
        secure_keywords = ["disallow-doctype-decl", "setFeature", "secure-processing", "setXIncludeAware"]
        if not any(kw in ctx for kw in secure_keywords):
            findings.append({
                "type": "XML External Entity (XXE)",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "medium",
                "engine": "regex",
                "symbol": "DocumentBuilderFactory",
                "detail": "XML 解析器未禁用外部实体和 DOCTYPE 声明，存在 XXE 攻击风险",
            })

    # Insecure Deserialization: ObjectInputStream.readObject()
    for m in re.finditer(r'ObjectInputStream', source):
        ctx = source[m.start():m.start() + 300]
        if "readObject" in ctx:
            findings.append({
                "type": "Insecure Deserialization",
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "high",
                "engine": "regex",
                "symbol": "ObjectInputStream",
                "detail": "使用 ObjectInputStream.readObject() 反序列化数据，未进行类型过滤，可能导致远程代码执行",
            })

    # Hardcoded credentials
    for m in re.finditer(r'(password|secret|token|api_key|apikey)\s*=\s*"[^"]{4,}"', source, re.IGNORECASE):
        findings.append({
            "type": "Hardcoded Secret",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "medium",
            "engine": "regex",
            "symbol": m.group(1),
            "detail": f"检测到硬编码的敏感信息: {m.group(1)}",
        })

    return findings


def _regex_scan_c_cpp(file_path: str) -> list[dict[str, Any]]:
    """基于正则的 C/C++ 漏洞检测（tree-sitter 不可用时的回退）."""
    source = _read_source(file_path)
    findings: list[dict[str, Any]] = []

    # Buffer Overflow: strcpy, strcat, gets, sprintf
    dangerous_funcs = {
        "strcpy": "Buffer Overflow",
        "strcat": "Buffer Overflow",
        "gets": "Buffer Overflow",
        "sprintf": "Buffer Overflow",
        "vsprintf": "Buffer Overflow",
        "scanf": "Buffer Overflow",
    }
    for func_name, vuln_type in dangerous_funcs.items():
        for m in re.finditer(r'\b' + re.escape(func_name) + r'\s*\(', source):
            findings.append({
                "type": vuln_type,
                "file": file_path,
                "line": _line_of(source, m.start()),
                "severity": "ERROR",
                "confidence": "high",
                "engine": "regex",
                "symbol": func_name,
                "detail": f"使用不安全的 {func_name} 函数，可能导致缓冲区溢出",
            })

    # Format String: printf(user_input)
    for m in re.finditer(r'\bprintf\s*\(\s*(?!")(\w+)', source):
        findings.append({
            "type": "Format String Vulnerability",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "high",
            "engine": "regex",
            "symbol": "printf",
            "detail": "printf 的第一个参数可能是用户控制的，存在格式化字符串攻击风险",
        })

    # Command Injection: system(), popen()
    for m in re.finditer(r'\b(system|popen)\s*\(', source):
        findings.append({
            "type": "Command Injection",
            "file": file_path,
            "line": _line_of(source, m.start()),
            "severity": "ERROR",
            "confidence": "medium",
            "engine": "regex",
            "symbol": m.group(1),
            "detail": f"使用 {m.group(1)} 执行外部命令，如果参数包含用户输入，可能导致命令注入攻击",
        })

    # Memory Leak: malloc without free
    alloc_vars = set()
    free_vars = set()
    for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
        alloc_vars.add(m.group(1))
    for m in re.finditer(r'free\s*\(\s*(\w+)', source):
        free_vars.add(m.group(1))
    for var in alloc_vars - free_vars:
        # 找到 malloc 行号
        for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
            if m.group(1) == var:
                findings.append({
                    "type": "Memory Leak",
                    "file": file_path,
                    "line": _line_of(source, m.start()),
                    "severity": "WARNING",
                    "confidence": "low",
                    "engine": "regex",
                    "symbol": "malloc",
                    "detail": f"变量 {var} 分配的内存可能未释放，建议检查所有代码路径",
                })
                break

    # TOCTOU: access() followed by open()
    lines = source.split("\n")
    for i, line in enumerate(lines):
        if re.search(r'\baccess\s*\(', line):
            # 检查后续 10 行是否有 open
            for j in range(i + 1, min(i + 10, len(lines))):
                if re.search(r'\bopen\s*\(', lines[j]):
                    findings.append({
                        "type": "Race Condition (TOCTOU)",
                        "file": file_path,
                        "line": j + 1,
                        "severity": "WARNING",
                        "confidence": "medium",
                        "engine": "regex",
                        "symbol": "access/open",
                        "detail": "先检查文件权限再打开文件存在竞争条件（TOCTOU）",
                    })
                    break

    return findings
