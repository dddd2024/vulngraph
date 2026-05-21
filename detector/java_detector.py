"""
基于 Tree-sitter 的 Java 漏洞检测器

支持检测的漏洞类型：
- SQL 注入 (SQL Injection) - JDBC Statement 字符串拼接
- 命令注入 (Command Injection) - Runtime.exec() / ProcessBuilder
- 路径穿越 (Path Traversal) - File/Path 操作未校验
- XSS 跨站脚本 (Cross-Site Scripting) - JSP/Servlet 输出未编码
- 不安全的反序列化 (Insecure Deserialization) - ObjectInputStream.readObject()
- LDAP 注入 (LDAP Injection) - JNDI/LDAP 查询拼接
- XXE (XML External Entity) - DocumentBuilder 未禁用外部实体
- 日志注入 (Log Injection) - 用户输入直接写入日志

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

# SQL 注入：JDBC 中使用 Statement + 字符串拼接
SQL_DANGEROUS_PATTERNS = [
    "createstatement",
    "executequery",
    "executeupdate",
    "execute(",
    "executequery",
]

# SQL 注入：字符串拼接 SQL 的关键词
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR"]

# 命令注入
CMD_DANGEROUS_FUNCTIONS = [
    "Runtime.getRuntime",
    "ProcessBuilder",
    "exec(",
]

# 路径穿越
PATH_DANGEROUS_OPERATIONS = [
    "file(",
    "fileinputstream",
    "fileoutputstream",
    "filereader",
    "filewriter",
    "files.read",
    "files.write",
    "files.lines",
    "paths.get(",
    "new file(",
    "bufferedreader",
    "bufferedwriter",
]

# 反序列化
DESERIALIZATION_PATTERNS = [
    "ObjectInputStream",
    "readObject(",
    "readUnshared(",
]

# XXE
XXE_PATTERNS = [
    "DocumentBuilderFactory",
    "SAXParserFactory",
    "XMLInputFactory",
    "TransformerFactory",
]

# LDAP 注入
LDAP_PATTERNS = [
    "InitialDirContext",
    "DirContext",
    "search(",
    "lookup(",
]


class JavaDetector:
    """
    Java 漏洞检测器

    使用 Tree-sitter 进行 AST 分析 + 上下文模式匹配，识别 Java 代码中的安全漏洞。
    """

    def __init__(self):
        self.parser = get_parser()

    def detect_file(self, file_path: str) -> list[Vulnerability]:
        """检测文件中的漏洞"""
        parsed = self.parser.parse_file(file_path)
        if not parsed or parsed.language != LanguageType.JAVA:
            return []
        return self.detect_parsed(parsed)

    def detect_parsed(self, parsed: ParsedCode) -> list[Vulnerability]:
        """从解析结果中检测漏洞"""
        vulnerabilities = []

        vulnerabilities.extend(self._detect_sql_injection(parsed))
        vulnerabilities.extend(self._detect_command_injection(parsed))
        vulnerabilities.extend(self._detect_path_traversal(parsed))
        vulnerabilities.extend(self._detect_xss(parsed))
        vulnerabilities.extend(self._detect_insecure_deserialization(parsed))
        vulnerabilities.extend(self._detect_xxe(parsed))
        vulnerabilities.extend(self._detect_ldap_injection(parsed))
        vulnerabilities.extend(self._detect_log_injection(parsed))

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
            "request.getparameter",
            "request.getparametervalues",
            "request.getheader",
            "request.getinputstream",
            "request.getreader",
            "@requestparam",
            "@pathvariable",
            "@queryparam",
            "@requestbody",
            "httpservletrequest",
            "getparameter(",
            "getattribute(",
        ]
        if any(p in ctx for p in input_patterns):
            return True

        # 检查当前行是否引用了方法参数（可能是用户输入）
        line = self._get_line(parsed, line_num).lower()
        # 如果行中有括号内的变量引用，可能是方法参数
        if re.search(r'\(\s*\w+\s*\)', line):
            # 检查该变量是否是方法参数
            for func in parsed.functions:
                if func.line <= line_num <= func.end_line:
                    for param in func.params:
                        if param.lower() in line:
                            return True
                            break

        return False

    def _has_string_concat(self, parsed: ParsedCode, line_num: int) -> bool:
        """检查是否有字符串拼接"""
        line = self._get_line(parsed, line_num)
        # Java 字符串拼接: "..." + variable
        return bool(re.search(r'"\s*\+\s*\w+', line) or re.search(r'\w+\s*\+\s*"', line))

    def _has_sql_keywords(self, parsed: ParsedCode, line_num: int) -> bool:
        """检查是否包含 SQL 关键字"""
        ctx = self._get_context(parsed, line_num, 3).upper()
        return any(kw in ctx for kw in SQL_KEYWORDS)

    # ---- 检测方法 ----

    def _detect_sql_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测 SQL 注入

        典型模式：
          Statement stmt = conn.createStatement();
          String sql = "SELECT * FROM users WHERE id=" + userId;
          ResultSet rs = stmt.executeQuery(sql);
        """
        findings = []
        source_lines = parsed.source.split("\n")

        # 策略1：检查方法调用中的 SQL 拼接
        for call in parsed.calls:
            callee = (call.callee or "").lower()
            is_sql = any(p in callee for p in SQL_DANGEROUS_PATTERNS)
            if not is_sql:
                continue

            # 检查该调用行及上下文是否有拼接或 SQL 关键字
            has_concat = self._has_string_concat(parsed, call.line)
            has_sql = self._has_sql_keywords(parsed, call.line)
            has_input = self._has_user_input(parsed, call.line)

            if has_concat and has_sql:
                confidence = "high" if has_input else "medium"
                findings.append(Vulnerability(
                    type="SQL Injection",
                    file=parsed.file_path,
                    line=call.line,
                    severity="ERROR",
                    confidence=confidence,
                    symbol=call.callee or "unknown",
                    detail=f"SQL 查询使用字符串拼接，存在 SQL 注入风险: {call.callee}()"
                ))

        # 策略2：检查 createStatement 后的上下文（多行模式）
        for call in parsed.calls:
            callee = (call.callee or "").lower()
            if "createstatement" not in callee:
                continue

            # 检查后续 10 行是否有字符串拼接 SQL
            for offset in range(1, 11):
                check_line = call.line + offset
                if check_line > len(source_lines):
                    break
                ctx_line = source_lines[check_line - 1]

                # 检查是否有 SQL 关键字 + 字符串拼接
                has_sql = any(kw in ctx_line.upper() for kw in SQL_KEYWORDS)
                has_concat = "+" in ctx_line and ('"' in ctx_line or "'" in ctx_line)

                if has_sql and has_concat:
                    has_input = self._has_user_input(parsed, check_line)
                    confidence = "high" if has_input else "medium"
                    findings.append(Vulnerability(
                        type="SQL Injection",
                        file=parsed.file_path,
                        line=check_line,
                        severity="ERROR",
                        confidence=confidence,
                        symbol="Statement.executeQuery",
                        detail="使用 Statement（非 PreparedStatement）执行拼接 SQL，建议改用 PreparedStatement"
                    ))
                    break

        return findings

    def _detect_command_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测命令注入

        典型模式：
          Runtime.getRuntime().exec("cmd " + userInput);
          new ProcessBuilder("cmd", userInput).start();
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            is_cmd = any(p.lower() in line_lower for p in CMD_DANGEROUS_FUNCTIONS)
            if not is_cmd:
                continue

            has_concat = self._has_string_concat(parsed, i)
            has_input = self._has_user_input(parsed, i)

            if has_concat or has_input:
                # 提取具体函数名
                symbol = "Runtime.exec"
                if "processbuilder" in line_lower:
                    symbol = "ProcessBuilder"
                elif "exec(" in line_lower:
                    symbol = "Runtime.exec"

                findings.append(Vulnerability(
                    type="Command Injection",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high" if has_input else "medium",
                    symbol=symbol,
                    detail=f"命令执行函数使用了不可信输入，存在命令注入风险: {symbol}"
                ))

        return findings

    def _detect_path_traversal(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测路径穿越

        典型模式：
          new File(request.getParameter("file"));
          Files.readAllBytes(Paths.get(request.getParameter("path")));
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            is_file_op = any(p.lower() in line_lower for p in PATH_DANGEROUS_OPERATIONS)
            if not is_file_op:
                continue

            has_input = self._has_user_input(parsed, i)

            if has_input:
                # 提取具体操作
                symbol = "File"
                if "fileinputstream" in line_lower:
                    symbol = "FileInputStream"
                elif "fileoutputstream" in line_lower:
                    symbol = "FileOutputStream"
                elif "files.read" in line_lower:
                    symbol = "Files.read"
                elif "files.write" in line_lower:
                    symbol = "Files.write"
                elif "paths.get" in line_lower:
                    symbol = "Paths.get"

                findings.append(Vulnerability(
                    type="Path Traversal",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high",
                    symbol=symbol,
                    detail=f"文件操作使用了用户可控的路径参数，存在路径穿越风险: {symbol}"
                ))

        return findings

    def _detect_xss(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测 XSS（JSP/Servlet 场景）

        典型模式：
          response.getWriter().write(request.getParameter("name"));
          out.print(request.getAttribute("content"));
        """
        findings = []
        source_lines = parsed.source.split("\n")

        xss_sinks = [
            "getwriter().write",
            "getwriter().println",
            ".print(",
            "out.print",
            "out.write",
            "out.println",
        ]

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            is_xss_sink = any(sink in line_lower for sink in xss_sinks)
            if not is_xss_sink:
                continue

            has_input = self._has_user_input(parsed, i)

            if has_input:
                findings.append(Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high",
                    symbol="response.getWriter",
                    detail="Servlet 输出直接使用了用户输入，未进行 HTML 编码，存在 XSS 风险"
                ))

        return findings

    def _detect_insecure_deserialization(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测不安全的反序列化

        典型模式：
          ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
          Object obj = ois.readObject();
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            has_deser = any(p.lower() in line_lower for p in DESERIALIZATION_PATTERNS)
            if not has_deser:
                continue

            # 检查是否有输入过滤
            ctx = self._get_context(parsed, i, 5).lower()
            has_filter = any(f in ctx for f in [
                "validatelist", "whitelist", "filter",
                "serializablefilter", "objectinputfilter",
                "securitycheck", "typecheck"
            ])

            if not has_filter:
                findings.append(Vulnerability(
                    type="Insecure Deserialization",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high",
                    symbol="ObjectInputStream",
                    detail="使用 ObjectInputStream.readObject() 反序列化数据，未进行类型过滤，可能导致远程代码执行"
                ))

        return findings

    def _detect_xxe(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测 XXE（XML 外部实体注入）

        典型模式：
          DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
          // 缺少: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            has_xml_factory = any(p.lower() in line_lower for p in XXE_PATTERNS)
            if not has_xml_factory:
                continue

            # 检查后续几行是否配置了安全特性
            ctx = self._get_context(parsed, i, 10).lower()
            has_secure_config = any(s in ctx for s in [
                "disallow-doctype-decl",
                "external-general-entities",
                "external-parameter-entities",
                "secure-processing",
                "setfeature",
                "setxincludeaware",
            ])

            if not has_secure_config:
                findings.append(Vulnerability(
                    type="XML External Entity (XXE)",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="medium",
                    symbol="DocumentBuilderFactory",
                    detail="XML 解析器未禁用外部实体和 DOCTYPE 声明，存在 XXE 攻击风险"
                ))

        return findings

    def _detect_ldap_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测 LDAP 注入

        典型模式：
          ctx.search("cn=" + userName + ",ou=users", controls);
        """
        findings = []
        source_lines = parsed.source.split("\n")

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            has_ldap = any(p.lower() in line_lower for p in LDAP_PATTERNS)
            if not has_ldap:
                continue

            has_concat = self._has_string_concat(parsed, i)
            has_input = self._has_user_input(parsed, i)

            if has_concat or has_input:
                findings.append(Vulnerability(
                    type="LDAP Injection",
                    file=parsed.file_path,
                    line=i,
                    severity="ERROR",
                    confidence="high" if has_input else "medium",
                    symbol="DirContext.search",
                    detail="LDAP 查询使用字符串拼接构造过滤条件，存在 LDAP 注入风险"
                ))

        return findings

    def _detect_log_injection(self, parsed: ParsedCode) -> list[Vulnerability]:
        """
        检测日志注入

        典型模式：
          logger.info("User login: " + username);
        """
        findings = []
        source_lines = parsed.source.split("\n")

        log_patterns = [
            "logger.info(", "logger.debug(", "logger.warn(", "logger.error(",
            "logger.trace(", "log.info(", "log.debug(", "log.warn(", "log.error(",
            "log4j", "logback",
        ]

        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            is_log = any(p in line_lower for p in log_patterns)
            if not is_log:
                continue

            has_input = self._has_user_input(parsed, i)
            has_concat = self._has_string_concat(parsed, i)

            if has_input and has_concat:
                findings.append(Vulnerability(
                    type="Log Injection",
                    file=parsed.file_path,
                    line=i,
                    severity="WARNING",
                    confidence="medium",
                    symbol="logger",
                    detail="日志输出直接拼接了用户输入，可能导致日志注入或伪造"
                ))

        return findings


# ---- 全局实例和便捷函数 ----

_global_detector: JavaDetector | None = None


def get_detector() -> JavaDetector:
    """获取全局 Java 检测器实例"""
    global _global_detector
    if _global_detector is None:
        _global_detector = JavaDetector()
    return _global_detector


def detect_java_vulnerabilities(file_path: str) -> list[dict[str, Any]]:
    """
    便捷函数：检测 Java 文件中的漏洞

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
    "Insecure Deserialization",
    "XML External Entity (XXE)",
    "LDAP Injection",
    "Log Injection",
]

SUPPORTED_LANGUAGES = ["java"]
