"""
Java pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like SQL injection, command injection,
path traversal, XXE, insecure deserialization, and hardcoded secrets.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class JavaPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in Java.
    
    Detects:
    - SQL Injection via executeQuery/executeUpdate with string concatenation
    - Command Injection via Runtime.exec / ProcessBuilder
    - Path Traversal via new File(user input)
    - XXE via DocumentBuilderFactory without secure config
    - Insecure Deserialization via ObjectInputStream.readObject
    - Hardcoded Secrets
    """
    
    name = "java_pattern"
    supported_languages = ["java"]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze Java code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language != "java":
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # SQL Injection
            findings.extend(self._detect_sql_injection(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # Path Traversal
            findings.extend(self._detect_path_traversal(unit, source, lines))
            
            # XXE
            findings.extend(self._detect_xxe(unit, source, lines))
            
            # Insecure Deserialization
            findings.extend(self._detect_deserialization(unit, source, lines))
            
            # Hardcoded Secrets
            findings.extend(self._detect_hardcoded_secret(unit, source, lines))
        
        return findings
    
    def _detect_sql_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SQL injection via executeQuery with string concatenation."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'(executeQuery|executeUpdate|execute)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 50]
            if '+' in ctx and any(kw in ctx.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SQL_001",
                    type="SQL Injection",
                    cwe="CWE-89",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"SQL query uses string concatenation: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via Runtime.exec / ProcessBuilder."""
        findings: list[RawFinding] = []
        
        # Runtime.exec pattern 1: direct call
        for m in re.finditer(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_CMD_001",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="Command execution via Runtime.exec with potential user input",
                engine=self.name,
                evidence={
                    "symbol": "Runtime.exec",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        # Runtime.exec pattern 2: getRuntime followed by exec
        for m in re.finditer(r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)', source):
            ctx = source[m.start():m.end() + 300]
            if re.search(r'\.\s*exec\s*\(', ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_CMD_002",
                    type="Command Injection",
                    cwe="CWE-78",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="Command execution via Runtime.exec with potential user input",
                    engine=self.name,
                    evidence={
                        "symbol": "Runtime.exec",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # ProcessBuilder
        for m in re.finditer(r'ProcessBuilder\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_CMD_003",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="ProcessBuilder with potential user input",
                engine=self.name,
                evidence={
                    "symbol": "ProcessBuilder",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_path_traversal(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect path traversal via new File(user input)."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'new\s+File\s*\(', source):
            ctx = source[max(0, m.start() - 50):m.end() + 100]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_PT_001",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="File operation with user-controlled path parameter",
                    engine=self.name,
                    evidence={
                        "symbol": "File",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_xxe(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XXE via DocumentBuilderFactory without secure config."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)', source):
            ctx = source[m.start():m.end() + 500]
            secure_keywords = ["disallow-doctype-decl", "setFeature", "secure-processing", "setXIncludeAware"]
            if not any(kw in ctx for kw in secure_keywords):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_XXE_001",
                    type="XML External Entity (XXE)",
                    cwe="CWE-611",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="XML parser without secure configuration (external entities enabled)",
                    engine=self.name,
                    evidence={
                        "symbol": "DocumentBuilderFactory",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_deserialization(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect insecure deserialization via ObjectInputStream.readObject."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'ObjectInputStream', source):
            ctx = source[m.start():m.start() + 300]
            if "readObject" in ctx:
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_DESER_001",
                    type="Insecure Deserialization",
                    cwe="CWE-502",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="ObjectInputStream.readObject() without type filtering (RCE risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "ObjectInputStream",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_hardcoded_secret(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect hardcoded secrets."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'(password|secret|token|api_key|apikey)\s*=\s*"[^"]{4,}"', source, re.IGNORECASE):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_SECRET_001",
                type="Hardcoded Secret",
                cwe="CWE-798",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Hardcoded secret detected: {m.group(1)}",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings