"""多语言漏洞检测测试.

验证 LanguageRouter 能正确路由不同语言的文件到对应检测器，
并验证每个 finding 都包含 language 字段。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"


class TestLanguageRouter:
    """LanguageRouter 基础功能测试."""

    def test_detect_language_python(self):
        """验证 Python 文件语言检测."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        lang = router.detect_language(str(FIXTURES_DIR / "python" / "vulnerable.py"))
        assert lang == "python"

    def test_detect_language_javascript(self):
        """验证 JavaScript 文件语言检测."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        lang = router.detect_language(str(FIXTURES_DIR / "javascript" / "vulnerable.js"))
        assert lang == "javascript"

    def test_detect_language_typescript(self):
        """验证 TypeScript 文件语言检测."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        lang = router.detect_language(str(FIXTURES_DIR / "typescript" / "vulnerable.ts"))
        assert lang == "typescript"

    def test_detect_language_java(self):
        """验证 Java 文件语言检测."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        lang = router.detect_language(str(FIXTURES_DIR / "java" / "Vulnerable.java"))
        assert lang == "java"

    def test_detect_language_c(self):
        """验证 C 文件语言检测."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        lang = router.detect_language(str(FIXTURES_DIR / "c" / "vulnerable.c"))
        assert lang == "c"

    def test_unsupported_language_returns_empty(self):
        """不支持的文件语言应返回空列表."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        # 创建一个临时 .go 文件（Go 不在路由器支持列表中）
        tmp_file = FIXTURES_DIR / "dummy.go"
        try:
            tmp_file.write_text("package main\nfunc main() {}", encoding="utf-8")
            findings = router.scan_file(str(tmp_file))
            assert findings == []
        finally:
            if tmp_file.exists():
                tmp_file.unlink()


class TestPythonDetection:
    """Python 漏洞检测测试."""

    def test_python_sql_injection(self):
        """验证 Python 可以检测 SQL Injection."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "python" / "vulnerable.py"))
        types = [f["type"] for f in findings]
        assert "SQL Injection" in types

    def test_python_command_injection(self):
        """验证 Python 可以检测 Command Injection."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "python" / "vulnerable.py"))
        types = [f["type"] for f in findings]
        assert "Command Injection" in types

    def test_python_findings_have_language(self):
        """验证 Python finding 包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "python" / "vulnerable.py"))
        for f in findings:
            assert "language" in f
            assert f["language"] == "Python"


class TestJavaScriptDetection:
    """JavaScript 漏洞检测测试."""

    def test_js_xss_detection(self):
        """验证 JS 可以检测 XSS."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "javascript" / "vulnerable.js"))
        types = [f["type"] for f in findings]
        assert "Cross-Site Scripting (XSS)" in types

    def test_js_eval_detection(self):
        """验证 JS 可以检测 eval 使用."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "javascript" / "vulnerable.js"))
        types = [f["type"] for f in findings]
        assert "Code Injection / Eval Usage" in types

    def test_js_command_injection(self):
        """验证 JS 可以检测命令注入."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "javascript" / "vulnerable.js"))
        types = [f["type"] for f in findings]
        assert "Command Injection" in types

    def test_js_findings_have_language(self):
        """验证 JS finding 包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "javascript" / "vulnerable.js"))
        for f in findings:
            assert "language" in f
            assert f["language"] == "JavaScript"


class TestTypeScriptDetection:
    """TypeScript 漏洞检测测试."""

    def test_ts_xss_detection(self):
        """验证 TS 可以检测 XSS."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "typescript" / "vulnerable.ts"))
        types = [f["type"] for f in findings]
        assert "Cross-Site Scripting (XSS)" in types

    def test_ts_eval_detection(self):
        """验证 TS 可以检测 eval 使用."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "typescript" / "vulnerable.ts"))
        types = [f["type"] for f in findings]
        assert "Code Injection / Eval Usage" in types

    def test_ts_findings_have_language(self):
        """验证 TS finding 包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "typescript" / "vulnerable.ts"))
        for f in findings:
            assert "language" in f
            assert f["language"] == "TypeScript"


class TestJavaDetection:
    """Java 漏洞检测测试."""

    def test_java_sql_injection(self):
        """验证 Java 可以检测 SQL Injection."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "java" / "Vulnerable.java"))
        types = [f["type"] for f in findings]
        assert "SQL Injection" in types

    def test_java_xxe(self):
        """验证 Java 可以检测 XXE."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "java" / "Vulnerable.java"))
        types = [f["type"] for f in findings]
        assert "XML External Entity (XXE)" in types

    def test_java_command_injection(self):
        """验证 Java 可以检测命令注入."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "java" / "Vulnerable.java"))
        types = [f["type"] for f in findings]
        assert "Command Injection" in types

    def test_java_findings_have_language(self):
        """验证 Java finding 包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "java" / "Vulnerable.java"))
        for f in findings:
            assert "language" in f
            assert f["language"] == "Java"


class TestCDetection:
    """C/C++ 漏洞检测测试."""

    def test_c_buffer_overflow(self):
        """验证 C 可以检测 strcpy 缓冲区溢出."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "c" / "vulnerable.c"))
        types = [f["type"] for f in findings]
        assert "Buffer Overflow" in types

    def test_c_format_string(self):
        """验证 C 可以检测 printf 格式化字符串漏洞."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "c" / "vulnerable.c"))
        types = [f["type"] for f in findings]
        assert "Format String Vulnerability" in types

    def test_c_command_injection(self):
        """验证 C 可以检测 system 命令注入."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "c" / "vulnerable.c"))
        types = [f["type"] for f in findings]
        assert "Command Injection" in types

    def test_c_findings_have_language(self):
        """验证 C finding 包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()
        findings = router.scan_file(str(FIXTURES_DIR / "c" / "vulnerable.c"))
        for f in findings:
            assert "language" in f
            assert f["language"] in ("C", "C/C++")


class TestCollectCodeFiles:
    """analysis_engine._collect_code_files 测试."""

    def test_collects_multiple_languages(self):
        """验证 _collect_code_files 能收集多种语言的文件."""
        from analysis_engine import _collect_code_files
        files = _collect_code_files(FIXTURES_DIR)
        extensions = {f.suffix.lower() for f in files}
        assert ".py" in extensions
        assert ".js" in extensions
        assert ".ts" in extensions
        assert ".java" in extensions
        assert ".c" in extensions

    def test_ignores_non_code_files(self):
        """验证 _collect_code_files 忽略非代码文件."""
        from analysis_engine import _collect_code_files
        files = _collect_code_files(FIXTURES_DIR)
        for f in files:
            assert f.suffix.lower() in {
                ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
                ".go", ".php", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".rs",
            }


class TestLanguageFieldInAllFindings:
    """验证所有语言的 finding 都包含 language 字段."""

    def test_all_languages_have_language_field(self):
        """所有支持语言的检测结果都应包含 language 字段."""
        from detector.core.language_router import LanguageRouter
        router = LanguageRouter()

        test_files = {
            "Python": FIXTURES_DIR / "python" / "vulnerable.py",
            "JavaScript": FIXTURES_DIR / "javascript" / "vulnerable.js",
            "TypeScript": FIXTURES_DIR / "typescript" / "vulnerable.ts",
            "Java": FIXTURES_DIR / "java" / "Vulnerable.java",
            "C": FIXTURES_DIR / "c" / "vulnerable.c",
        }

        for expected_lang, file_path in test_files.items():
            findings = router.scan_file(str(file_path))
            assert len(findings) > 0, f"{expected_lang} 应检测到至少一个漏洞"
            for f in findings:
                assert "language" in f, f"{expected_lang} finding 缺少 language 字段: {f}"
                assert f["language"] == expected_lang, (
                    f"{expected_lang} finding language 字段错误: "
                    f"期望 {expected_lang}, 实际 {f['language']}"
                )
