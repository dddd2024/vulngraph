"""
C/C++ pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like buffer overflow, format string,
command injection, memory leak, and race conditions.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class CPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in C/C++.
    
    Detects:
    - Buffer Overflow via strcpy/strcat/gets/sprintf
    - Format String via printf with user-controlled format
    - Command Injection via system/popen
    - Memory Leak via malloc without free
    - Race Condition (TOCTOU) via access followed by open
    """
    
    name = "c_pattern"
    supported_languages = ["c", "cpp"]
    
    # Dangerous functions for buffer overflow
    DANGEROUS_FUNCS = {
        "strcpy": "Buffer Overflow",
        "strcat": "Buffer Overflow",
        "gets": "Buffer Overflow",
        "sprintf": "Buffer Overflow",
        "vsprintf": "Buffer Overflow",
        "scanf": "Buffer Overflow",
    }
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze C/C++ code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language not in ("c", "cpp"):
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # Buffer Overflow
            findings.extend(self._detect_buffer_overflow(unit, source, lines))
            
            # Format String
            findings.extend(self._detect_format_string(unit, source, lines))
            
            # Command Injection
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # Memory Leak
            findings.extend(self._detect_memory_leak(unit, source, lines))
            
            # Race Condition (TOCTOU)
            findings.extend(self._detect_toctou(unit, source, lines))
        
        return findings
    
    def _detect_buffer_overflow(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect buffer overflow via dangerous functions."""
        findings: list[RawFinding] = []
        
        for func_name, vuln_type in self.DANGEROUS_FUNCS.items():
            for m in re.finditer(r'\b' + re.escape(func_name) + r'\s*\(', source):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="C_BOF_001",
                    type=vuln_type,
                    cwe="CWE-120",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Use of unsafe function {func_name}() - potential buffer overflow",
                    engine=self.name,
                    evidence={
                        "symbol": func_name,
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_format_string(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect format string vulnerability via printf with variable format."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\bprintf\s*\(\s*(?!")(\w+)', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_FMT_001",
                type="Format String Vulnerability",
                cwe="CWE-134",
                severity="ERROR",
                confidence="high",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message="printf with potentially user-controlled format string",
                engine=self.name,
                evidence={
                    "symbol": "printf",
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_command_injection(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect command injection via system/popen."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\b(system|popen)\s*\(', source):
            line_num = source[:m.start()].count("\n") + 1
            findings.append(RawFinding(
                rule_id="C_CMD_001",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence="medium",
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Use of {m.group(1)}() with potential user input",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                }
            ))
        
        return findings
    
    def _detect_memory_leak(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential memory leak via malloc without free."""
        findings: list[RawFinding] = []
        
        # Find all malloc assignments
        alloc_vars: set[str] = set()
        for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
            alloc_vars.add(m.group(1))
        
        # Find all free calls
        free_vars: set[str] = set()
        for m in re.finditer(r'free\s*\(\s*(\w+)', source):
            free_vars.add(m.group(1))
        
        # Report variables that are allocated but not freed
        for var in alloc_vars - free_vars:
            for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
                if m.group(1) == var:
                    line_num = source[:m.start()].count("\n") + 1
                    findings.append(RawFinding(
                        rule_id="C_MEM_001",
                        type="Memory Leak",
                        cwe="CWE-401",
                        severity="WARN",
                        confidence="low",
                        file_path=unit.path,
                        start_line=unit.start_line + line_num - 1,
                        message=f"Variable {var} allocated but not freed",
                        engine=self.name,
                        evidence={
                            "symbol": "malloc",
                            "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        }
                    ))
                    break
        
        return findings
    
    def _detect_toctou(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect race condition (TOCTOU) via access followed by open."""
        findings: list[RawFinding] = []
        
        for i, line in enumerate(lines):
            if re.search(r'\baccess\s*\(', line):
                # Check next 10 lines for open()
                for j in range(i + 1, min(i + 10, len(lines))):
                    if re.search(r'\bopen\s*\(', lines[j]):
                        findings.append(RawFinding(
                            rule_id="C_TOCTOU_001",
                            type="Race Condition (TOCTOU)",
                            cwe="CWE-367",
                            severity="WARN",
                            confidence="medium",
                            file_path=unit.path,
                            start_line=unit.start_line + j + 1,
                            message="Time-of-check to time-of-use (TOCTOU) race condition",
                            engine=self.name,
                            evidence={
                                "symbol": "access/open",
                                "matched_line": lines[j].strip(),
                            }
                        ))
                        break
        
        return findings