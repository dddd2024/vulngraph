"""
C/C++ pattern analyzer for detecting vulnerabilities.

Uses regex patterns to detect issues like buffer overflow, format string,
command injection, memory leak, race conditions, integer overflow,
use-after-free, null pointer dereference, and double free.
"""

import re
from typing import Any

from audit_core.models import CodeUnit, RawFinding
from analyzers.base import BaseAnalyzer


class CPatternAnalyzer(BaseAnalyzer):
    """
    Analyzer that uses regex patterns to detect vulnerabilities in C/C++.
    
    Detects:
    - Buffer Overflow via strcpy/strcat/gets/sprintf (with context-aware false positive reduction)
    - Format String via printf with user-controlled format
    - Command Injection via system/popen (with hardcoded string exclusion)
    - Memory Leak via malloc without free
    - Race Condition (TOCTOU) via access followed by open
    - Integer Overflow via unchecked arithmetic on user input
    - Use-After-Free via free followed by dereference
    - Null Pointer Dereference
    - Double Free
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
    
    # Safe alternatives that suppress warnings
    SAFE_ALTERNATIVES = {
        "strcpy": ["strncpy", "strcpy_s", "strlcpy"],
        "strcat": ["strncat", "strcat_s", "strlcat"],
        "gets": ["fgets", "gets_s"],
        "sprintf": ["snprintf", "sprintf_s"],
        "vsprintf": ["vsnprintf", "vsprintf_s"],
        "scanf": ["sscanf", "scanf_s", "fscanf"],
    }
    
    def analyze(self, code_units: list[CodeUnit]) -> list[RawFinding]:
        """Analyze C/C++ code units and return findings."""
        findings: list[RawFinding] = []
        
        for unit in code_units:
            if unit.language not in ("c", "cpp"):
                continue
            
            source = unit.content
            lines = source.split("\n")
            
            # Buffer Overflow (context-aware)
            findings.extend(self._detect_buffer_overflow(unit, source, lines))
            
            # Format String
            findings.extend(self._detect_format_string(unit, source, lines))
            
            # Command Injection (context-aware)
            findings.extend(self._detect_command_injection(unit, source, lines))
            
            # Memory Leak
            findings.extend(self._detect_memory_leak(unit, source, lines))
            
            # Race Condition (TOCTOU)
            findings.extend(self._detect_toctou(unit, source, lines))
            
            # Integer Overflow
            findings.extend(self._detect_integer_overflow(unit, source, lines))
            
            # Use-After-Free
            findings.extend(self._detect_use_after_free(unit, source, lines))
            
            # Null Pointer Dereference
            findings.extend(self._detect_null_dereference(unit, source, lines))
            
            # Double Free
            findings.extend(self._detect_double_free(unit, source, lines))
        
        return findings
    
    def _is_hardcoded_string(self, arg: str) -> bool:
        """Check if an argument is a hardcoded string literal (not user-controlled)."""
        arg = arg.strip()
        # Starts with " or L" and contains no format specifiers or variables
        if arg.startswith('"') and arg.endswith('"'):
            content = arg[1:-1]
            # Only %s, %n, %[0-9]*s, %[0-9]*n are dangerous in sprintf
            # %d, %f, %x, %c, %ld, %lu are safe (they don't cause buffer overflow)
            if not re.search(r'%(?:\d*\$)?[sn]', content):
                return True
        if arg.startswith('L"') and arg.endswith('"'):
            content = arg[2:-1]
            if not re.search(r'%(?:\d*\$)?[sn]', content):
                return True
        return False
    
    def _is_safe_alternative_used(self, source: str, func_name: str, match_pos: int) -> bool:
        """Check if a safe alternative is used nearby (within same function)."""
        safe_funcs = self.SAFE_ALTERNATIVES.get(func_name, [])
        if not safe_funcs:
            return False
        
        # Look backwards from the match position for a #define or comment
        # indicating intentional use, or check if the function is in a safe context
        for safe_func in safe_funcs:
            # Check if the dangerous function is commented out or in a #if 0 block
            pass
        
        return False
    
    def _detect_buffer_overflow(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect buffer overflow via dangerous functions with context-aware filtering."""
        findings: list[RawFinding] = []
        
        for func_name, vuln_type in self.DANGEROUS_FUNCS.items():
            for m in re.finditer(r'\b' + re.escape(func_name) + r'\s*\(', source):
                line_num = source[:m.start()].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                
                # Skip if the function is in a comment
                if self._is_in_comment(source, m.start()):
                    continue
                
                # Skip if the function is in a macro definition that maps to safe version
                if self._is_safe_macro(source, m.start(), func_name):
                    continue
                
                # For sprintf: check if format string is hardcoded with no %s
                if func_name == "sprintf":
                    args_after = source[m.end():m.end() + 200]
                    # For sprintf, first arg is destination, second is format string
                    args = re.findall(r'[^,)]+', args_after)
                    if len(args) >= 2:
                        fmt_arg = args[1].strip()
                        if self._is_hardcoded_string(fmt_arg):
                            # Check if the format string contains %s (still dangerous)
                            if '%s' not in fmt_arg and '%n' not in fmt_arg:
                                continue  # Safe: hardcoded format without %s or %n
                
                # For gets: always report (no safe usage)
                # For strcpy/strcat: check if source is a string literal
                if func_name in ("strcpy", "strcat"):
                    args_after = source[m.end():m.end() + 200]
                    # Extract second argument for strcpy, first for strcat context
                    args = re.findall(r'[^,)]+', args_after)
                    if len(args) >= 2 and func_name == "strcpy":
                        src_arg = args[1].strip()
                        if self._is_hardcoded_string(src_arg):
                            continue  # Safe: copying from hardcoded string
                
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
                        "matched_line": matched_line,
                    }
                ))
        
        return findings
    
    def _is_in_comment(self, source: str, pos: int) -> bool:
        """Check if a position is inside a comment."""
        # Check for // comment on the same line
        line_start = source.rfind("\n", 0, pos) + 1
        line_before_pos = source[line_start:pos]
        if "//" in line_before_pos:
            return True
        
        # Check for /* */ block comment
        last_open = source.rfind("/*", 0, pos)
        last_close = source.rfind("*/", 0, pos)
        if last_open != -1 and (last_close == -1 or last_open > last_close):
            return True
        
        return False
    
    def _is_safe_macro(self, source: str, pos: int, func_name: str) -> bool:
        """Check if the dangerous function is wrapped in a safe macro."""
        # Look for patterns like: #define strcpy strncpy
        line_start = source.rfind("\n", 0, pos) + 1
        # This is a simplified check
        return False
    
    def _detect_format_string(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect format string vulnerability via printf with variable format."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\bprintf\s*\(\s*(?!")(\w+)', source):
            # Skip if in comment
            if self._is_in_comment(source, m.start()):
                continue
            
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
        """Detect command injection via system/popen with context-aware filtering."""
        findings: list[RawFinding] = []
        
        for m in re.finditer(r'\b(system|popen)\s*\(', source):
            # Skip if in comment
            if self._is_in_comment(source, m.start()):
                continue
            
            line_num = source[:m.start()].count("\n") + 1
            matched_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            # Extract the argument to system/popen
            args_after = source[m.end():m.end() + 200]
            arg_match = re.match(r'\s*([^,)]+)', args_after)
            
            if arg_match:
                arg = arg_match.group(1).strip()
                
                # Skip if the argument is a hardcoded string literal
                if self._is_hardcoded_string(arg):
                    continue
                
                # Check if argument is a simple variable (potentially user-controlled)
                # but also check if it was validated/sanitized before
                ctx_before = source[max(0, m.start() - 300):m.start()]
                
                # Check for sanitization patterns
                has_sanitization = any(s in ctx_before for s in [
                    "shlex_quote", "escapeshellcmd", "sanitized",
                    "validated", "whitelist", "allowlist"
                ])
                
                confidence = "medium" if not has_sanitization else "low"
            else:
                confidence = "medium"
            
            findings.append(RawFinding(
                rule_id="C_CMD_001",
                type="Command Injection",
                cwe="CWE-78",
                severity="ERROR",
                confidence=confidence,
                file_path=unit.path,
                start_line=unit.start_line + line_num - 1,
                message=f"Use of {m.group(1)}() with potential user input",
                engine=self.name,
                evidence={
                    "symbol": m.group(1),
                    "matched_line": matched_line,
                }
            ))
        
        return findings
    
    def _detect_memory_leak(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential memory leak via malloc without free."""
        findings: list[RawFinding] = []
        
        # Find all malloc/calloc/new assignments
        alloc_vars: set[str] = set()
        for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(', source):
            alloc_vars.add(m.group(1))
        
        # C++ new operator
        for m in re.finditer(r'(\w+)\s*=\s*new\s+', source):
            alloc_vars.add(m.group(1))
        
        # Find all free/delete calls
        free_vars: set[str] = set()
        for m in re.finditer(r'free\s*\(\s*(\w+)', source):
            free_vars.add(m.group(1))
        for m in re.finditer(r'delete\s+(\w+)', source):
            free_vars.add(m.group(1))
        
        # Find variables returned from function (ownership transferred)
        return_vars: set[str] = set()
        for m in re.finditer(r'return\s+(\w+)\s*;', source):
            return_vars.add(m.group(1))
        
        # Report variables that are allocated but not freed
        leaked_vars = alloc_vars - free_vars - return_vars
        for var in leaked_vars:
            for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(', source):
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
                        message=f"Variable '{var}' allocated but not freed",
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
    
    def _detect_integer_overflow(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential integer overflow in size calculations."""
        findings: list[RawFinding] = []
        
        # Pattern: malloc(a * b) without overflow check
        for m in re.finditer(r'malloc\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)', source):
            line_num = source[:m.start()].count("\n") + 1
            matched_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            # Check if there's an overflow check before this line
            ctx_before = source[max(0, m.start() - 300):m.start()]
            has_overflow_check = any(kw in ctx_before for kw in [
                "overflow", "SIZE_MAX", "INT_MAX", "safe_mul",
                "checked", "__builtin_mul_overflow", "mul_overflow"
            ])
            
            if not has_overflow_check:
                findings.append(RawFinding(
                    rule_id="C_INT_001",
                    type="Integer Overflow",
                    cwe="CWE-190",
                    severity="WARN",
                    confidence="medium",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Potential integer overflow in malloc({m.group(1)} * {m.group(2)})",
                    engine=self.name,
                    evidence={
                        "symbol": "malloc(a*b)",
                        "matched_line": matched_line,
                    }
                ))
        
        # Pattern: unchecked array index from user input
        for m in re.finditer(r'(?:argv|argc|atoi|strtol|atol|sscanf)\b', source):
            ctx = source[m.start():min(len(source), m.start() + 200)]
            if re.search(r'\[\s*\w+\s*\]', ctx):
                line_num = source[:m.start()].count("\n") + 1
                findings.append(RawFinding(
                    rule_id="C_INT_002",
                    type="Integer Overflow",
                    cwe="CWE-190",
                    severity="WARN",
                    confidence="low",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message="User input used as array index without bounds check",
                    engine=self.name,
                    evidence={
                        "symbol": m.group(1),
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
        
        return findings
    
    def _detect_use_after_free(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect use-after-free via free followed by dereference."""
        findings: list[RawFinding] = []
        
        # Find free(var) and check if var is used afterwards
        for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', source):
            freed_var = m.group(1)
            free_line = source[:m.start()].count("\n")
            
            # Check next 20 lines for usage of freed variable
            after_free = source[m.end():]
            after_lines = after_free.split("\n")[:20]
            
            for i, line in enumerate(after_lines):
                # Check if the freed variable is dereferenced
                if re.search(r'\b' + re.escape(freed_var) + r'\b', line):
                    # But skip if it's another free, a NULL check, or reassignment
                    if re.search(r'free\s*\(\s*' + re.escape(freed_var), line):
                        continue
                    if re.search(r'if\s*\(\s*!' + re.escape(freed_var), line):
                        continue
                    if re.search(r'if\s*\(\s*' + re.escape(freed_var) + r'\s*==\s*(NULL|0|nullptr)', line):
                        continue
                    if re.search(re.escape(freed_var) + r'\s*=', line):
                        continue
                    
                    line_num = free_line + i + 1
                    if line_num < len(lines):
                        findings.append(RawFinding(
                            rule_id="C_UAF_001",
                            type="Use-After-Free",
                            cwe="CWE-416",
                            severity="ERROR",
                            confidence="medium",
                            file_path=unit.path,
                            start_line=unit.start_line + line_num,
                            message=f"Variable '{freed_var}' used after free()",
                            engine=self.name,
                            evidence={
                                "symbol": freed_var,
                                "matched_line": lines[line_num].strip(),
                            }
                        ))
                        break  # Only report once per free
        
        return findings
    
    def _detect_null_dereference(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential null pointer dereference."""
        findings: list[RawFinding] = []
        
        # Pattern: malloc result used without NULL check
        for m in re.finditer(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', source):
            var = m.group(1)
            malloc_line = source[:m.start()].count("\n")
            
            # Check next 5 lines for NULL check
            after = source[m.end():]
            after_lines = after.split("\n")[:5]
            
            has_null_check = False
            for line in after_lines:
                if re.search(r'if\s*\(\s*!' + re.escape(var) + r'\b', line):
                    has_null_check = True
                    break
                if re.search(r'if\s*\(\s*' + re.escape(var) + r'\s*==\s*(NULL|0|nullptr)\)', line):
                    has_null_check = True
                    break
                if re.search(r'if\s*\(\s*' + re.escape(var) + r'\s*!=\s*(NULL|0|nullptr)\)', line):
                    has_null_check = True
                    break
            
            if not has_null_check:
                # Check if variable is dereferenced before any check
                for i, line in enumerate(after_lines):
                    if re.search(r'if\s*\(', line):
                        break  # Stop at any if statement
                    if re.search(re.escape(var) + r'\s*\[', line):
                        line_num = malloc_line + i + 1
                        if line_num < len(lines):
                            findings.append(RawFinding(
                                rule_id="C_NULL_001",
                                type="Null Pointer Dereference",
                                cwe="CWE-476",
                                severity="WARN",
                                confidence="medium",
                                file_path=unit.path,
                                start_line=unit.start_line + line_num,
                                message=f"Variable '{var}' from malloc() used without NULL check",
                                engine=self.name,
                                evidence={
                                    "symbol": var,
                                    "matched_line": lines[line_num].strip(),
                                }
                            ))
                            break
        
        return findings
    
    def _detect_double_free(self, unit: CodeUnit, source: str, lines: list[str]) -> list[RawFinding]:
        """Detect potential double free."""
        findings: list[RawFinding] = []
        
        # Track free(var) calls
        freed_vars: dict[str, int] = {}  # var -> first free line number
        for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', source):
            var = m.group(1)
            line_num = source[:m.start()].count("\n") + 1
            
            if var in freed_vars:
                # Double free detected
                findings.append(RawFinding(
                    rule_id="C_DBLFREE_001",
                    type="Double Free",
                    cwe="CWE-415",
                    severity="ERROR",
                    confidence="high",
                    file_path=unit.path,
                    start_line=unit.start_line + line_num - 1,
                    message=f"Variable '{var}' freed more than once (double free)",
                    engine=self.name,
                    evidence={
                        "symbol": var,
                        "matched_line": lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    }
                ))
            else:
                freed_vars[var] = line_num
        
        return findings