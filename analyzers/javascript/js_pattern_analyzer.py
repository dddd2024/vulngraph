"""
JavaScript/TypeScript pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like XSS, eval usage, command injection,
and SQL injection in JavaScript and TypeScript code.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class JSPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in JavaScript/TypeScript.
    
    Detects:
    - Cross-Site Scripting (XSS) via innerHTML/outerHTML assignment
    - XSS via Express response sinks with user input
    - Code Injection via eval() / Function()
    - Command Injection via exec() / spawn()
    - SQL Injection via query() with string concatenation
    """
    
    name = "js_pattern"
    supported_languages = ["javascript", "typescript"]
    
    # XSS patterns
    XSS_HTML_PATTERNS = [
        (r'\.\s*(innerHTML|outerHTML)\s*=', "Cross-Site Scripting (XSS)", "CWE-79",
         "medium", "Potential XSS: HTML assignment with unsanitized content"),
    ]
    
    # Express XSS source pattern
    EXPRESS_XSS_SOURCE = re.compile(r'req(?:uest)?\.(?:query|body|params)', re.IGNORECASE)
    
    # Eval patterns
    EVAL_PATTERNS = [
        (r'\b(eval|Function)\s*\(', "Code Injection / Eval Usage", "CWE-95",
         "medium", "Dangerous dynamic code execution"),
    ]
    
    # Command Injection patterns
    COMMAND_PATTERNS = [
        (r'\b(exec|execSync|execFileSync|spawn|spawnSync)\s*\(', "Command Injection", "CWE-78",
         "medium", "Potential command injection"),
    ]
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        (r'\.(query|execute|raw|sql)\s*\(', "SQL Injection", "CWE-89",
         "medium", "Potential SQL injection with string concatenation"),
    ]
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze JavaScript/TypeScript code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language not in ("javascript", "typescript"):
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # XSS: innerHTML / outerHTML
            findings.extend(self._detect_xss_html(unit, source, lines))
            
            # XSS: Express response sinks
            findings.extend(self._detect_xss_express(unit, source, lines))
            
            # Eval usage
            findings.extend(self._detect_eval(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # SQL Injection
            findings.extend(self._detect_sql_injection(unit, source, lines))
        
        return findings
    
    def _detect_xss_html(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XSS via innerHTML/outerHTML assignment."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.XSS_HTML_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id=f"JS_XSS_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=message,
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_xss_express(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XSS via Express response sinks with user input."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\bres\.\s*(send|write|end|render)\s*\(', source):
            sink_name = f"res.{m.group(1)}"
            
            # Check context for user input
            ctx_start = max(0, m.start() - 300)
            ctx_end = min(len(source), m.end() + 100)
            ctx = source[ctx_start:ctx_end]
            
            has_user_input = bool(self.EXPRESS_XSS_SOURCE.search(ctx))
            has_concat = '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx)
            
            if has_user_input or has_concat:
                line_num = source[:m.start()].count("\n") + 1
                confidence = "high" if has_user_input else "medium"
                findings.append(RawFinding(
                    rule_id="JS_XSS_002",
                    type="Cross-Site Scripting (XSS)",
                    cwe="CWE-79",
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Express XSS: {sink_name}() with {'user input' if has_user_input else 'string concatenation'}",
                    engine=self.name,
                    evidence={
                        "symbol": sink_name,
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_eval(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect eval() / Function() usage."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.EVAL_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_EVAL_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="WARN",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{message}: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via exec/spawn."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.COMMAND_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_CMD_001",
                    type=vuln_type,
                    cwe=cwe,
                    severity="ERROR",
                    confidence=confidence,
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{message}: {m.group(1)}()",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_sql_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SQL injection via query() with concatenation."""
        findings: list[RawFinding] = []
        
        for pattern, vuln_type, cwe, confidence, message in self.SQL_PATTERNS:
            for m in re.finditer(pattern, source):
                # Check context for string concatenation
                ctx = source[max(0, m.start() - 100):m.end() + 100]
                if '+' in ctx and ('"' in ctx or "'" in ctx or '`' in ctx):
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="JS_SQL_001",
                        type=vuln_type,
                        cwe=cwe,
                        severity="ERROR",
                        confidence=confidence,
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"{message}: {m.group(1)}()",
                        engine=self.name,
                        evidence={
                            "symbol": m.group(1),
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        return findings