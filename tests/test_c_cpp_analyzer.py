"""
Tests for C/C++ pattern analyzer.

Verifies detection of:
- Buffer Overflow (with context-aware false positive reduction)
- Format String
- Command Injection (with hardcoded string exclusion)
- Memory Leak
- Race Condition (TOCTOU)
- Integer Overflow
- Use-After-Free
- Null Pointer Dereference
- Double Free
"""

import pytest
from audit_core.models import CodeUnit, RawFinding
from analyzers.c_cpp.c_pattern_analyzer import CPatternAnalyzer


# ---------------------------------------------------------------------------
# Test code snippets
# ---------------------------------------------------------------------------

BUFFER_OVERFLOW_CODE = '''
#include <string.h>

void copy_data(char *dest, char *src) {
    strcpy(dest, src);
    strcat(dest, "extra");
    gets(dest);
    sprintf(dest, "Value: %s", src);
}
'''

FORMAT_STRING_CODE = '''
#include <stdio.h>

void print_message(char *fmt, char *arg) {
    printf(fmt, arg);
    printf(user_format);
}
'''

COMMAND_INJECTION_CODE = '''
#include <stdlib.h>

void run_command(char *cmd) {
    system(cmd);
    popen(cmd, "r");
}
'''

MEMORY_LEAK_CODE = '''
#include <stdlib.h>

void allocate_memory() {
    char *buffer = malloc(1024);
    char *data = malloc(512);
    // No free() calls
}
'''

TOCTOU_CODE = '''
#include <unistd.h>
#include <fcntl.h>

void check_and_open(char *path) {
    if (access(path, R_OK) == 0) {
        int fd = open(path, O_RDONLY);
        // Race condition between access and open
    }
}
'''

CLEAN_CODE = '''
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

void safe_copy(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
}
'''

# --- New test snippets for enhanced detection ---

# Hardcoded system() - should NOT be reported
HARDCODED_SYSTEM_CODE = '''
#include <stdlib.h>

void run_ls() {
    system("ls -la");
    popen("echo hello", "r");
}
'''

# Commented out dangerous function - should NOT be reported
COMMENTED_DANGEROUS_CODE = '''
#include <string.h>

void copy_data(char *dest, char *src) {
    // strcpy(dest, src);  // This is commented out
    strncpy(dest, src, 256);
}
'''

# Safe sprintf with no %s - should NOT be reported
SAFE_SPRINTF_CODE = '''
#include <stdio.h>

void print_value(int x) {
    char buf[64];
    sprintf(buf, "Value: %d", x);
    printf("%s\\n", buf);
}
'''

# Safe strcpy from literal - should NOT be reported
SAFE_STRCPY_CODE = '''
#include <string.h>

void init_buffer(char *buf) {
    strcpy(buf, "Hello World");
}
'''

INTEGER_OVERFLOW_CODE = '''
#include <stdlib.h>

void allocate_buffer(int width, int height) {
    char *pixels = malloc(width * height);
    pixels[0] = 0;
}
'''

USE_AFTER_FREE_CODE = '''
#include <stdlib.h>
#include <stdio.h>

void use_after_free_example() {
    char *data = malloc(100);
    strcpy(data, "hello");
    free(data);
    printf("Data: %s\\n", data);
}
'''

DOUBLE_FREE_CODE = '''
#include <stdlib.h>

void double_free_example() {
    char *data = malloc(100);
    free(data);
    free(data);
}
'''

NULL_DEREF_CODE = '''
#include <stdlib.h>

void null_deref_example() {
    char *buf = malloc(1024);
    buf[0] = 'a';
}
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_unit(code: str, path: str = "test.c", lang: str = "c") -> CodeUnit:
    return CodeUnit(path=path, language=lang, content=code, start_line=1)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerBasic:

    def test_analyzer_name(self):
        assert CPatternAnalyzer().name == "c_pattern"

    def test_supported_languages(self):
        analyzer = CPatternAnalyzer()
        assert "c" in analyzer.supported_languages
        assert "cpp" in analyzer.supported_languages

    def test_skips_non_c(self):
        analyzer = CPatternAnalyzer()
        unit = CodeUnit(path="test.py", language="python", content="eval(code)", start_line=1)
        results = analyzer.analyze([unit])
        assert results == []

    def test_empty_code_units(self):
        analyzer = CPatternAnalyzer()
        results = analyzer.analyze([])
        assert results == []

    def test_clean_code_no_findings(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(CLEAN_CODE)
        results = analyzer.analyze([unit])
        # strncpy is safe, so no findings
        assert len(results) == 0


class TestCPatternAnalyzerBufferOverflow:

    def test_detects_strcpy(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) > 0

        finding = bof_findings[0]
        assert finding.cwe == "CWE-120"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"

    def test_detects_multiple_dangerous_funcs(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        symbols = [f.evidence.get("symbol") for f in results if "Buffer Overflow" in f.type]
        assert "strcpy" in symbols
        assert "strcat" in symbols
        assert "gets" in symbols

    def test_detects_sprintf(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        sprintf_findings = [f for f in results if f.evidence.get("symbol") == "sprintf"]
        assert len(sprintf_findings) > 0


class TestCPatternAnalyzerFormatString:

    def test_detects_format_string(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(FORMAT_STRING_CODE)
        results = analyzer.analyze([unit])

        fmt_findings = [f for f in results if "Format String" in f.type]
        assert len(fmt_findings) > 0

        finding = fmt_findings[0]
        assert finding.cwe == "CWE-134"
        assert finding.severity == "ERROR"


class TestCPatternAnalyzerCommandInjection:

    def test_detects_system(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) > 0

        finding = cmd_findings[0]
        assert finding.cwe == "CWE-78"
        assert finding.severity == "ERROR"

    def test_detects_popen(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(COMMAND_INJECTION_CODE)
        results = analyzer.analyze([unit])

        popen_findings = [f for f in results if f.evidence.get("symbol") == "popen"]
        assert len(popen_findings) > 0


class TestCPatternAnalyzerMemoryLeak:

    def test_detects_memory_leak(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(MEMORY_LEAK_CODE)
        results = analyzer.analyze([unit])

        leak_findings = [f for f in results if "Memory Leak" in f.type]
        assert len(leak_findings) > 0

        finding = leak_findings[0]
        assert finding.cwe == "CWE-401"
        assert finding.severity == "WARN"
        assert finding.confidence == "low"


class TestCPatternAnalyzerTOCTOU:

    def test_detects_toctou(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(TOCTOU_CODE)
        results = analyzer.analyze([unit])

        toctou_findings = [f for f in results if "TOCTOU" in f.type or "Race Condition" in f.type]
        assert len(toctou_findings) > 0

        finding = toctou_findings[0]
        assert finding.cwe == "CWE-367"
        assert finding.severity == "WARN"


class TestCPatternAnalyzerCpp:

    def test_analyzes_cpp(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE, path="test.cpp", lang="cpp")
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) > 0


class TestCPatternAnalyzerFindingFormat:

    def test_findings_are_raw_finding(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        for finding in results:
            assert isinstance(finding, RawFinding)
            assert finding.rule_id
            assert finding.type
            assert finding.file_path
            assert finding.start_line > 0
            assert finding.engine == "c_pattern"

    def test_file_path_preserved(self):
        analyzer = CPatternAnalyzer()
        unit = _make_unit(BUFFER_OVERFLOW_CODE, path="src/utils/strings.c")
        results = analyzer.analyze([unit])

        for finding in results:
            assert finding.file_path == "src/utils/strings.c"


# ---------------------------------------------------------------------------
# New tests: Context-aware false positive reduction
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerFalsePositiveReduction:

    def test_hardcoded_system_not_reported(self):
        """system() with hardcoded string should NOT be reported."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(HARDCODED_SYSTEM_CODE)
        results = analyzer.analyze([unit])

        cmd_findings = [f for f in results if "Command Injection" in f.type]
        assert len(cmd_findings) == 0, "Hardcoded system() should not be reported"

    def test_commented_strcpy_not_reported(self):
        """Commented-out strcpy should NOT be reported."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(COMMENTED_DANGEROUS_CODE)
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) == 0, "Commented-out strcpy should not be reported"

    def test_safe_sprintf_not_reported(self):
        """sprintf with hardcoded format and no %s should NOT be reported."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(SAFE_SPRINTF_CODE)
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) == 0, "Safe sprintf should not be reported"

    def test_safe_strcpy_from_literal_not_reported(self):
        """strcpy from hardcoded string literal should NOT be reported."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(SAFE_STRCPY_CODE)
        results = analyzer.analyze([unit])

        bof_findings = [f for f in results if "Buffer Overflow" in f.type]
        assert len(bof_findings) == 0, "strcpy from literal should not be reported"


# ---------------------------------------------------------------------------
# New tests: Integer Overflow
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerIntegerOverflow:

    def test_detects_integer_overflow_malloc(self):
        """Should detect integer overflow in malloc(a * b)."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(INTEGER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        int_findings = [f for f in results if "Integer Overflow" in f.type]
        assert len(int_findings) > 0, "Should detect integer overflow in malloc(a*b)"

    def test_integer_overflow_has_cwe190(self):
        """Integer overflow should reference CWE-190."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(INTEGER_OVERFLOW_CODE)
        results = analyzer.analyze([unit])

        int_findings = [f for f in results if "Integer Overflow" in f.type]
        assert any(f.cwe == "CWE-190" for f in int_findings)


# ---------------------------------------------------------------------------
# New tests: Use-After-Free
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerUseAfterFree:

    def test_detects_use_after_free(self):
        """Should detect use-after-free."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(USE_AFTER_FREE_CODE)
        results = analyzer.analyze([unit])

        uaf_findings = [f for f in results if "Use-After-Free" in f.type]
        assert len(uaf_findings) > 0, "Should detect use-after-free"

    def test_use_after_free_has_cwe416(self):
        """Use-after-free should reference CWE-416."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(USE_AFTER_FREE_CODE)
        results = analyzer.analyze([unit])

        uaf_findings = [f for f in results if "Use-After-Free" in f.type]
        assert any(f.cwe == "CWE-416" for f in uaf_findings)


# ---------------------------------------------------------------------------
# New tests: Double Free
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerDoubleFree:

    def test_detects_double_free(self):
        """Should detect double free."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(DOUBLE_FREE_CODE)
        results = analyzer.analyze([unit])

        df_findings = [f for f in results if "Double Free" in f.type]
        assert len(df_findings) > 0, "Should detect double free"

    def test_double_free_has_cwe415(self):
        """Double free should reference CWE-415."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(DOUBLE_FREE_CODE)
        results = analyzer.analyze([unit])

        df_findings = [f for f in results if "Double Free" in f.type]
        assert any(f.cwe == "CWE-415" for f in df_findings)

    def test_double_free_confidence_high(self):
        """Double free should have high confidence."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(DOUBLE_FREE_CODE)
        results = analyzer.analyze([unit])

        df_findings = [f for f in results if "Double Free" in f.type]
        assert all(f.confidence == "high" for f in df_findings)


# ---------------------------------------------------------------------------
# New tests: Null Pointer Dereference
# ---------------------------------------------------------------------------

class TestCPatternAnalyzerNullDeref:

    def test_detects_null_deref(self):
        """Should detect null pointer dereference."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(NULL_DEREF_CODE)
        results = analyzer.analyze([unit])

        null_findings = [f for f in results if "Null Pointer" in f.type]
        assert len(null_findings) > 0, "Should detect null pointer dereference"

    def test_null_deref_has_cwe476(self):
        """Null deref should reference CWE-476."""
        analyzer = CPatternAnalyzer()
        unit = _make_unit(NULL_DEREF_CODE)
        results = analyzer.analyze([unit])

        null_findings = [f for f in results if "Null Pointer" in f.type]
        assert any(f.cwe == "CWE-476" for f in null_findings)