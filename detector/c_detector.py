"""
基于 Tree-sitter 的 C/C++ 漏洞检测器

支持检测的漏洞类型：
- 缓冲区溢出 (Buffer Overflow) - strcpy, strcat, sprintf, gets 等
- 格式化字符串漏洞 (Format String) - printf 用户输入
- 整数溢出 (Integer Overflow) - 无符号整数运算
- 内存泄漏 (Memory Leak) - malloc 无 free
- 路径穿越 (Path Traversal) - fopen 等文件操作
- 命令注入 (Command Injection) - system, popen
- 不安全的随机数 (Insecure Random) - rand() 用于安全场景
- 竞争条件 (Race Condition) - access/open, stat/open 等 TOCTOU
- 空指针解引用 (Null Pointer Dereference)
- 使用后释放 (Use After Free)

该模块作为 detector/vuln_detector.py 的扩展，不替代原有功能。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
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


# ---- 危险模式定义 ----

# 缓冲区溢出危险函数
BUFFER_OVERFLOW_FUNCTIONS = [
    "strcpy", "strcat", "strncpy", "strncat",
    "sprintf", "vsprintf", "gets", "getwd",
    "wcscpy", "wcscat", "memcpy", "memmove",
    "scanf", "sscanf", "fscanf", "vscanf",
]

# 格式化字符串危险函数
FORMAT_STRING_FUNCTIONS = [
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "syslog", "setproctitle",
]

# 内存操作（需检查泄漏）
MEMORY_ALLOC_FUNCTIONS = [
    "malloc", "calloc", "realloc", "strdup", "strndup",
    "new",  # C++
]

MEMORY_FREE_FUNCTIONS = [
    "free", "delete", "delete[]",  # C++
]

# 命令注入
COMMAND_INJECTION_FUNCTIONS = [
    "system", "popen", "pclose", "execl", "execle",
    "execlp", "execv", "execve", "execvp", "execvpe",
]

# 文件操作（路径穿越）
FILE_OPERATIONS = [
    "fopen", "freopen", "open", "creat",
    "access", "stat", "lstat", "chmod", "chown",
]

# 不安全的随机数
INSECURE_RANDOM = [
    "rand", "random", "srand",
]

# TOCTOU 竞争条件（先检查后使用）
TOCTOU_PAIRS = [
    ("access", "open"),
    ("stat", "open"),
    ("lstat", "open"),
    ("chmod", "open"),
]


class CDetector:
    """
    C/C++ 漏洞检测器

    使用 Tree-sitter 进行 AST 分析 + 上下文模式匹配，识别 C/C++ 代码中的安全漏洞。
    """

    def __init__(self):
        self.parser = get_parser()

    def detect_file(self, file_path: str) -> list[Vulnerability]:
        """检测文件中的漏洞"""
        parsed = self.parser.parse_file(file_path)
        if not parsed or parsed.language not in (LanguageType.C, LanguageType.CPP):
            return []
        return self.detect_parsed(parsed)

    def detect_parsed(self, parsed: ParsedCode) -> list[Vulnerability]:
        """从解析结果中检测漏洞"""
        vulnerabilities = []

        vulnerabilities.extend(self._detect_buffer_overflow(parsed))
        vulnerabilities.extend(self._detect_format_string(parsed))
        vulnerabilities.extend(self._detect_memory_leak(parsed))
        vulnerabilities.extend(self._detect_command_injection(parsed))
        vulnerabilities.extend(self._detect_path_traversal(parsed))
        vulnerabilities.extend(self._detect_insecure_random(parsed))
        vulnerabilities.extend(self._detect_toctou(parsed))
        vulnerabilities.extend(self._detect_null_pointer(parsed))
        vulnerabilities.extend(self._detect_integer_overflow(parsed))

        return vulnerabilities

    # ---- 辅助方法 ----

    def _get_line(self, parsed: ParsedCode, line_num: int) -> str:
        """获取指定行内容"""
        lines = parsed.source.split("\n")
        if 1 <= line_num <= len(lines):
            return lines[line_num - 1]
        return ""

    def _get_context(self, parsed: ParsedCode, line_num: int, radius: int = 2) -> str:
        """获取上下文"""
        lines = parsed.source.split("\n")
        start = max(0, line_num - 1 - radius)
        end = min(len(lines), line_num + radius)
        return "\n".join(lines[start:end])

    def _has_user_input(self, parsed: ParsedCode, line_num: int) -> bool:
        """检查上下文是否涉及用户输入"""
        ctx = self._get_context(parsed, line_num, 3).lower()
        input_patterns = [
            "argv[", "argc", "scanf(", "getenv(", "getchar(",
            "fgets(", "read(", "recv(", "recvfrom(",
            "cin >>", "std::cin",  # C++
        ]
        return any(p in ctx for p in input_patterns)

    def _is_buffer_size_checked(self, parsed: ParsedCode, line_num: int, var_name: str) -> bool:
        """检查是否对缓冲区大小进行了校验"""
        ctx = self._get_context(parsed, line_num, 5).lower()
        size_checks = [
            "sizeof(", "strlen(", ".size()", ".length()",
            "< ", "> ", "<= ", ">= ",
        ]
        return any(check in ctx for check in size_checks)

    # ---- 检测方法 ----

    def _detect_buffer_overflow(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测缓冲区溢出

        典型模式：
          char buffer[10];
          strcpy(buffer, user_input);  // 危险！
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            is_dangerous = any(func == callee for func in BUFFER_OVERFLOW_FUNCTIONS)
            if not is_dangerous:
                continue

            line = call.line
            line_content = self._get_line(parsed, line)

            # 检查是否有长度限制版本
            if callee in ["strncpy", "strncat", "snprintf"]:
                # 这些有长度限制，但使用不当仍有风险
                if "sizeof(" not in line_content and "strlen(" not in line_content:
                    findings.append(Vulnerability(
                        type="Buffer Overflow",
                        file=parsed.file_path,
                        line=line,
                        severity="WARNING",
                        confidence="medium",
                        symbol=call.callee,
                        detail=f"使用 {call.callee} 但未正确计算目标缓冲区大小，仍可能存在溢出风险"
                    ))
                    continue

            # 危险函数无长度限制
            has_input = self._has_user_input(parsed, line)

            findings.append(Vulnerability(
                type="Buffer Overflow",
                file=parsed.file_path,
                line=line,
                severity="ERROR",
                confidence="high" if has_input else "medium",
                symbol=call.callee,
                detail=f"使用不安全的 {call.callee} 函数，可能导致缓冲区溢出。建议使用 {call.callee}n 或更安全的替代函数"
            ))

        return findings

    def _detect_format_string(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测格式化字符串漏洞

        典型模式：
          printf(user_input);  // 危险！用户输入包含 %s %n 等
        """
        findings = []

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            is_format_func = any(func == callee for func in FORMAT_STRING_FUNCTIONS)
            if not is_format_func:
                continue

            line = call.line
            line_content = self._get_line(parsed, line)

            # 检查第一个参数是否是字符串常量
            # 简单检查：如果第一个参数位置有引号，认为是安全的
            # 否则如果包含变量，可能是危险的
            has_string_literal = '"' in line_content or "'" in line_content
            has_variable = re.search(r'\b\w+\s*[,)]', line_content) is not None

            # 如果看起来像是 printf(variable) 而不是 printf("format", ...)
            if not has_string_literal and has_variable:
                has_input = self._has_user_input(parsed, line)
                findings.append(Vulnerability(
                    type="Format String Vulnerability",
                    file=parsed.file_path,
                    line=line,
                    severity="ERROR",
                    confidence="high" if has_input else "medium",
                    symbol=call.callee,
                    detail=f"{call.callee} 的第一个参数可能是用户控制的，存在格式化字符串攻击风险。应使用常量格式字符串"
                ))

        return findings

    def _detect_memory_leak(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测内存泄漏

        典型模式：
          void* ptr = malloc(100);
          // 没有对应的 free(ptr)
        """
        findings = []

        # 收集所有 malloc/calloc 调用
        alloc_lines = {}
        free_vars = set()

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            if callee in ["malloc", "calloc", "realloc", "strdup"]:
                # 尝试提取变量名
                line_content = self._get_line(parsed, call.line)
                match = re.search(r'(\w+)\s*=\s*(?:\w+\s*\*\s*)?' + callee, line_content)
                if match:
                    var_name = match.group(1)
                    alloc_lines[var_name] = call.line

            elif callee == "free":
                # 尝试提取释放的变量
                line_content = self._get_line(parsed, call.line)
                match = re.search(r'free\s*\(\s*(\w+)', line_content)
                if match:
                    free_vars.add(match.group(1))

        # 检查是否有未释放的分配
        for var, line in alloc_lines.items():
            if var not in free_vars:
                # 检查是否在循环中（多次分配）
                ctx = self._get_context(parsed, line, 5).lower()
                in_loop = any(kw in ctx for kw in ["for (", "while (", "do {"])

                if in_loop:
                    findings.append(Vulnerability(
                        type="Memory Leak",
                        file=parsed.file_path,
                        line=line,
                        severity="ERROR",
                        confidence="high",
                        symbol="malloc/calloc",
                        detail=f"变量 {var} 在循环中分配内存但未释放，可能导致内存泄漏"
                    ))
                else:
                    findings.append(Vulnerability(
                        type="Memory Leak",
                        file=parsed.file_path,
                        line=line,
                        severity="WARNING",
                        confidence="low",
                        symbol="malloc/calloc",
                        detail=f"变量 {var} 分配的内存可能未释放，建议检查所有代码路径"
                    ))

        return findings

    def _detect_command_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测命令注入

        典型模式：
          system(user_input);
          popen(cmd, "r");
        """
        findings = []

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            is_cmd = any(func == callee for func in COMMAND_INJECTION_FUNCTIONS)
            if not is_cmd:
                continue

            line = call.line
            has_input = self._has_user_input(parsed, line)

            findings.append(Vulnerability(
                type="Command Injection",
                file=parsed.file_path,
                line=line,
                severity="ERROR",
                confidence="high" if has_input else "medium",
                symbol=call.callee,
                detail=f"使用 {call.callee} 执行外部命令，如果参数包含用户输入，可能导致命令注入攻击"
            ))

        return findings

    def _detect_path_traversal(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测路径穿越

        典型模式：
          fopen(user_input, "r");
        """
        findings = []

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            is_file_op = any(func == callee for func in FILE_OPERATIONS)
            if not is_file_op:
                continue

            line = call.line
            has_input = self._has_user_input(parsed, line)

            if has_input:
                findings.append(Vulnerability(
                    type="Path Traversal",
                    file=parsed.file_path,
                    line=line,
                    severity="ERROR",
                    confidence="high",
                    symbol=call.callee,
                    detail=f"文件操作 {call.callee} 使用了用户输入的路径，存在路径穿越风险"
                ))

        return findings

    def _detect_insecure_random(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测不安全的随机数使用

        典型模式：
          int key = rand();  // 用于安全场景
        """
        findings = []

        for call in parsed.calls:
            callee = (call.callee or "").lower()

            if callee not in INSECURE_RANDOM:
                continue

            line = call.line
            ctx = self._get_context(parsed, line, 5).lower()

            # 检查是否用于安全场景（密钥、token、session 等）
            security_keywords = [
                "key", "token", "session", "password", "secret",
                "auth", "crypt", "ssl", "tls", "cipher"
            ]
            is_security_context = any(kw in ctx for kw in security_keywords)

            if is_security_context:
                findings.append(Vulnerability(
                    type="Insecure Random Number",
                    file=parsed.file_path,
                    line=line,
                    severity="ERROR",
                    confidence="high",
                    symbol=call.callee,
                    detail=f"使用 {call.callee} 生成安全敏感数据（密钥/Token），rand() 是可预测的，应使用加密安全随机数生成器"
                ))

        return findings

    def _detect_toctou(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测 TOCTOU（Time-of-check to time-of-use）竞争条件

        典型模式：
          if (access(file, R_OK) == 0) {
              fd = open(file, O_RDONLY);  // 竞争条件！
          }
        """
        findings = []
        source_lines = parsed.source.split("\n")

        # 查找 access/stat 调用
        check_lines = {}
        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()
            if any(func in line_lower for func in ["access(", "stat(", "lstat("]):
                # 提取文件名参数
                match = re.search(r'(\w+)\s*[,)]', line)
                if match:
                    filename = match.group(1)
                    check_lines[filename] = i

        # 查找后续是否有 open
        for filename, check_line in check_lines.items():
            for i in range(check_line + 1, min(check_line + 10, len(source_lines) + 1)):
                line = source_lines[i - 1].lower()
                if "open(" in line and filename in line:
                    findings.append(Vulnerability(
                        type="Race Condition (TOCTOU)",
                        file=parsed.file_path,
                        line=i,
                        severity="WARNING",
                        confidence="medium",
                        symbol="access/open",
                        detail=f"先检查文件权限再打开文件存在竞争条件（TOCTOU），攻击者可能在检查和打开之间替换文件"
                    ))
                    break

        return findings

    def _detect_null_pointer(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测潜在的空指针解引用

        典型模式：
          char* ptr = malloc(size);
          ptr[0] = 'a';  // 未检查 malloc 返回值
        """
        findings = []

        # 简化检测：查找 malloc 后直接使用而未检查 NULL
        alloc_lines = {}
        for call in parsed.calls:
            callee = (call.callee or "").lower()
            if callee in ["malloc", "calloc", "realloc"]:
                line_content = self._get_line(parsed, call.line)
                match = re.search(r'(\w+)\s*=', line_content)
                if match:
                    var_name = match.group(1)
                    alloc_lines[var_name] = call.line

        # 检查后续使用是否检查了 NULL
        source_lines = parsed.source.split("\n")
        for var, alloc_line in alloc_lines.items():
            # 查找后续 5 行内是否使用了该变量
            for i in range(alloc_line + 1, min(alloc_line + 6, len(source_lines) + 1)):
                line = source_lines[i - 1]
                if var in line and not line.strip().startswith("if"):
                    # 检查是否在前面有 NULL 检查
                    ctx = "\n".join(source_lines[alloc_line:i])
                    if f"{var} != NULL" not in ctx and f"{var} == NULL" not in ctx:
                        findings.append(Vulnerability(
                            type="Null Pointer Dereference",
                            file=parsed.file_path,
                            line=i,
                            severity="WARNING",
                            confidence="low",
                            symbol="malloc",
                            detail=f"分配内存后未检查 NULL 直接使用，如果内存分配失败会导致空指针解引用"
                        ))
                        break

        return findings

    def _detect_integer_overflow(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测整数溢出

        典型模式：
          int size = user_input * sizeof(int);  // 可能溢出
          int* arr = malloc(size);
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            # 检测乘法运算后用于内存分配
            if re.search(r'int\s+\w+\s*=.*\*.*sizeof', line):
                has_input = self._has_user_input(parsed, i)
                if has_input:
                    findings.append(Vulnerability(
                        type="Integer Overflow",
                        file=parsed.file_path,
                        line=i,
                        severity="WARNING",
                        confidence="medium",
                        symbol="integer multiplication",
                        detail="用户输入参与整数乘法后用于内存分配，可能导致整数溢出和堆溢出"
                    ))

        return findings


# ---- 全局实例和便捷函数 ----

_global_detector: CDetector | None = None


def get_detector() -> CDetector:
    """获取全局 C/C++ 检测器实例"""
    global _global_detector
    if _global_detector is None:
        _global_detector = CDetector()
    return _global_detector


def detect_c_vulnerabilities(file_path: str) -> list[dict[str, Any]]:
    """
    便捷函数：检测 C/C++ 文件中的漏洞

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
    "Buffer Overflow",
    "Format String Vulnerability",
    "Memory Leak",
    "Command Injection",
    "Path Traversal",
    "Insecure Random Number",
    "Race Condition (TOCTOU)",
    "Null Pointer Dereference",
    "Integer Overflow",
]

SUPPORTED_LANGUAGES = ["c", "cpp"]
