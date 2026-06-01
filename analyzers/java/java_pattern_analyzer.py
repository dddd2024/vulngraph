"""
Java pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like SQL injection, command injection,
path traversal, XXE, insecure deserialization, SSRF, and hardcoded secrets.
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
    - Path Traversal via new File(user input) / Paths.get()
    - XXE via DocumentBuilderFactory without secure config
    - Insecure Deserialization via ObjectInputStream.readObject / XMLDecoder
    - SSRF via URL/HttpURLConnection with user input
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
            
            # SSRF
            findings.extend(self._detect_ssrf(unit, source, lines))
            
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
        """Detect path traversal via new File(user input) / Paths.get() / transferTo."""
        findings: list[RawFinding] = []
        
        # Pattern 1: new File(user input)
        for m in re.finditer(r'new\s+File\s*\(', source):
            ctx = source[max(0, m.start() - 50):m.end() + 100]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
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
        
        # Pattern 2: Paths.get(user input) — Java NIO
        for m in re.finditer(r'Paths\s*\.\s*get\s*\(', source):
            ctx = source[max(0, m.start() - 50):m.end() + 100]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_PT_002",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="Paths.get() with user-controlled path parameter",
                    engine=self.name,
                    evidence={
                        "symbol": "Paths.get",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 3: Spring transferTo / Resource with user input
        for m in re.finditer(r'\.transferTo\s*\(', source):
            ctx = source[max(0, m.start() - 100):m.end() + 50]
            if any(p in ctx for p in ["MultipartFile", "getParameter", "getOriginalFilename"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_PT_003",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="File transfer with user-controlled filename (transferTo)",
                    engine=self.name,
                    evidence={
                        "symbol": "transferTo",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 4: FileInputStream / FileOutputStream with user input
        for m in re.finditer(r'(FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(', source):
            ctx = source[max(0, m.start() - 100):m.end() + 50]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_PT_004",
                    type="Path Traversal",
                    cwe="CWE-22",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{m.group(1)} with user-controlled path",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
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
        """Detect insecure deserialization via ObjectInputStream / XMLDecoder / Kryo / Jackson."""
        findings: list[RawFinding] = []
        
        # Pattern 1: ObjectInputStream.readObject
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
        
        # Pattern 2: XMLDecoder.readObject — extremely dangerous
        for m in re.finditer(r'XMLDecoder', source):
            ctx = source[m.start():m.start() + 300]
            if "readObject" in ctx:
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_DESER_002",
                    type="Insecure Deserialization",
                    cwe="CWE-502",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="XMLDecoder.readObject() allows arbitrary code execution",
                    engine=self.name,
                    evidence={
                        "symbol": "XMLDecoder",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 3: Kryo.readObject without type filtering
        for m in re.finditer(r'Kryo\s*\.\s*readObject', source):
            ctx = source[m.start():max(len(source), m.start() + 300)]
            if not any(kw in ctx for kw in ["setClassLoader", "setDefaultSerializer", "typeResolver"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_DESER_003",
                    type="Insecure Deserialization",
                    cwe="CWE-502",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="Kryo deserialization without type filtering",
                    engine=self.name,
                    evidence={
                        "symbol": "Kryo.readObject",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 4: Jackson enableDefaultTyping — allows arbitrary class instantiation
        for m in re.finditer(r'enableDefaultTyping', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_DESER_004",
                type="Insecure Deserialization",
                cwe="CWE-502",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="Jackson ObjectMapper.enableDefaultTyping() allows arbitrary class instantiation",
                engine=self.name,
                evidence={
                    "symbol": "enableDefaultTyping",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        # Pattern 5: Hessian / Burlap deserialization
        for m in re.finditer(r'(HessianInput|Hessian2Input|BurlapInput)\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="JAVA_DESER_005",
                type="Insecure Deserialization",
                cwe="CWE-502",
                severity="WARN",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"{m.group(1)} deserialization may allow remote code execution",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_ssrf(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect SSRF via URL/HttpURLConnection/RestTemplate/OkHttp with user input."""
        findings: list[RawFinding] = []
        
        # Pattern 1: new URL(user input)
        for m in re.finditer(r'new\s+URL\s*\(', source):
            ctx = source[max(0, m.start() - 100):m.end() + 50]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam", "request"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SSRF_001",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="URL construction with user-controlled input (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "URL",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 2: HttpURLConnection with user input
        for m in re.finditer(r'(HttpURLConnection|HttpsURLConnection|URLConnection)\s*\.', source):
            ctx = source[max(0, m.start() - 100):m.start() + 200]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SSRF_002",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"{m.group(1)} with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 3: RestTemplate / WebClient with user input
        for m in re.finditer(r'(RestTemplate|WebClient|UriComponentsBuilder)', source):
            ctx = source[m.start():max(len(source), m.start() + 300)]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                # Check if followed by an HTTP method call
                if re.search(r'\.(getForObject|getForEntity|postForObject|postForEntity|fromUriString|fromHttpUrl|build|get|post|put|delete|retrieve)\s*\(', ctx):
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="JAVA_SSRF_003",
                        type="SSRF",
                        cwe="CWE-918",
                        severity="ERROR",
                        confidence="high",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Spring {m.group(1)} with user-controlled URL (SSRF risk)",
                        engine=self.name,
                        evidence={
                            "symbol": m.group(1),
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
        
        # Pattern 4: OkHttp with user input
        for m in re.finditer(r'\.newCall\s*\(\s*Request\.Builder', source):
            ctx = source[max(0, m.start() - 200):m.end() + 100]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SSRF_004",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="OkHttp request with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": "OkHttp",
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        # Pattern 5: HttpClient / CloseableHttpClient with user input
        for m in re.finditer(r'(HttpClient|CloseableHttpClient)\s*\.\s*(execute|Get|Post)\s*\(', source):
            ctx = source[max(0, m.start() - 100):m.end() + 50]
            if any(p in ctx for p in ["getParameter", "getHeader", "PathVariable", "RequestParam", "queryParam"]):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="JAVA_SSRF_005",
                    type="SSRF",
                    cwe="CWE-918",
                    severity="ERROR",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Apache {m.group(1)} with user-controlled URL (SSRF risk)",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
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