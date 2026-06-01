"""
JavaScript/TypeScript pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like XSS, eval usage, command injection,
SQL injection, SSRF, and path traversal in JavaScript and TypeScript code.
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
    - XSS via document.write / React dangerouslySetInnerHTML
    - Code Injection via eval() / Function()
    - Command Injection via exec() / spawn()
    - SQL Injection via query() with string concatenation
    - SSRF via fetch / axios / http.request with user input
    - Path Traversal via fs operations with user input
    """
    
    name = "js_pattern"
    supported_languages = ["javascript", "typescript"]
    
    # XSS patterns
    XSS_HTML_PATTERNS = [
        (r'\.\s*(innerHTML|outerHTML)\s*=', "Cross-Site Scripting (XSS)", "CWE-79",
         "medium", "Potential XSS: HTML assignment with unsanitized content"),
    ]
    
    # Express XSS source pattern
    EXPRESS_XSS_SOURCE = re.compile(r'req(?:uest)?\.(?:query|body|params|headers|cookies)', re.IGNORECASE)
    
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
    
    # SSRF source pattern
    SSRF_SOURCE = re.compile(r'req(?:uest)?\.(?:query|body|params|headers)', re.IGNORECASE)
    
    # Path traversal source pattern
    PT_SOURCE = re.compile(r'req(?:uest)?\.(?:query|body|params|headers|files)', re.IGNORECASE)
    
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
            
            # XSS: document.write / dangerouslySetInnerHTML
            findings.extend(self._detect_xss_advanced(unit, source, lines))
            
            # Eval usage
            findings.extend(self._detect_eval(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # SQL Injection
            findings.extend(self._detect_sql_injection(unit, source, lines))
            
            # SSRF
            findings.extend(self._detect_ssrf(unit, source, lines))
            
            # Path Traversal
            findings.extend(self._detect_path_traversal(unit, source, lines))
        
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
    
    def _detect_xss_advanced(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect XSS via document.write / dangerouslySetInnerHTML / jQuery.html()."""
        findings: list[RawFinding] = []
        
        # Pattern 1: document.write with user input
        for m in re.finditer(r'\bdocument\s*\.\s*write\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.EXPRESS_XSS_SOURCE.search(ctx) or any(s in ctx for s in ['req.', 'params', 'query']):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_XSS_003",
                    type="Cross-Site Scripting (XSS)",
                    cwe="CWE-79",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="document.write() with user-controlled content",
                    engine=self.name,
                    evidence={
                        "symbol": "document.write",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 2: React dangerouslySetInnerHTML
        for m in re.finditer(r'dangerouslySetInnerHTML', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JS_XSS_004",
                type="Cross-Site Scripting (XSS)",
                cwe="CWE-79",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="React dangerouslySetInnerHTML bypasses XSS protection",
                engine=self.name,
                evidence={
                    "symbol": "dangerouslySetInnerHTML",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        # Pattern 3: jQuery .html() with user input
        for m in re.finditer(r'\$\s*\(\s*["\'][^"\']*["\']\s*\)\s*\.\s*html\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.EXPRESS_XSS_SOURCE.search(ctx) or any(s in ctx for s in ['req.', 'params']):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_XSS_005",
                    type="Cross-Site Scripting (XSS)",
                    cwe="CWE-79",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="jQuery .html() with user-controlled content",
                    engine=self.name,
                    evidence={
                        "symbol": "$.html()",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_ssrf(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SSRF via fetch / axios / http.request with user input."""
        findings: list[RawFinding] = []
        
        # Pattern 1: fetch() with user-controlled URL
        for m in re.finditer(r'\bfetch\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.SSRF_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_SSRF_001",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="fetch() with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "fetch",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 2: axios.get/post/put/delete with user input
        for m in re.finditer(r'axios\s*\.\s*(get|post|put|delete|patch|request)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.SSRF_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_SSRF_002",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"axios.{m.group(1)}() with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": f"axios.{m.group(1)}",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 3: http.request / https.request with user input
        for m in re.finditer(r'(?:http|https)\s*\.\s*request\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.SSRF_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_SSRF_003",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="http.request() with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "http.request",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 4: node-fetch / got / superagent with user input
        for m in re.finditer(r'\b(got|request|superagent)\s*\(\s*', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.SSRF_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_SSRF_004",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{m.group(1)}() with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 5: new URL() with user input (potential SSRF source)
        for m in re.finditer(r'new\s+URL\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 50]
            if self.SSRF_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_SSRF_005",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="WARN",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="new URL() constructed with user-controlled input",
                    engine=self.name,
                    evidence={
                        "symbol": "URL",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_path_traversal(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect path traversal via fs operations with user input."""
        findings: list[RawFinding] = []
        
        # Pattern 1: fs.readFile / fs.writeFile / fs.unlink with user input
        for m in re.finditer(r'fs\s*\.\s*(readFile|writeFile|unlink|readFileSync|writeFileSync|unlinkSync|appendFile|appendFileSync|mkdir|rmdir|stat|exists|createReadStream|createWriteStream)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.PT_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_PT_001",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"fs.{m.group(1)}() with user-controlled path",
                    engine=self.name,
                    evidence={
                        "symbol": f"fs.{m.group(1)}",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 2: path.join with user input
        for m in re.finditer(r'path\s*\.\s*join\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.PT_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_PT_002",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="WARN",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="path.join() with user-controlled component",
                    engine=self.name,
                    evidence={
                        "symbol": "path.join",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 3: res.sendFile / res.download with user input
        for m in re.finditer(r'res\s*\.\s*(sendFile|download)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if self.PT_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_PT_003",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"res.{m.group(1)}() with user-controlled file path",
                    engine=self.name,
                    evidence={
                        "symbol": f"res.{m.group(1)}",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 4: Express static with user input
        for m in re.finditer(r'app\s*\.\s*(use|static)\s*\(', source):
            ctx = source[max(0, m.start() - 200):m.end() + 200]
            if self.PT_SOURCE.search(ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JS_PT_004",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="WARN",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="Express static/serve with user-controlled path",
                    engine=self.name,
                    evidence={
                        "symbol": "express.static",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings