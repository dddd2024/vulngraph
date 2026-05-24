"""代码片段多语言检测测试.

验证 analyze_input(input_type="code") 能正确处理非 Python 代码片段，
包括语言识别、文件保存、漏洞检测和 language 字段。
"""

from __future__ import annotations

import pytest
from pathlib import Path

from analysis_engine import analyze_input, _write_code_snippet
import tempfile


# 测试用的漏洞代码片段
JAVASCRIPT_XSS_CODE = """
const express = require('express');
const app = express();

// XSS vulnerability
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send('<div id="output"></div><script>document.getElementById("output").innerHTML = "' + name + '";</script>');
});

app.listen(3000);
"""

JAVA_SQL_INJECTION_CODE = """
import java.sql.*;

public class TestClass {
    public void searchUser(String userId) throws Exception {
        Connection conn = null;
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id=" + userId;
        ResultSet rs = stmt.executeQuery(sql);
    }
}
"""

C_BUFFER_OVERFLOW_CODE = """
#include <stdio.h>
#include <string.h>

void copy_user_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);
}

int main(int argc, char *argv[]) {
    copy_user_input(argv[1]);
    return 0;
}
"""

PYTHON_SQL_CODE = """
def search_user(name):
    sql = "SELECT * FROM users WHERE name='" + name + "'"
    return conn.execute(sql).fetchall()
"""


class TestWriteCodeSnippet:
    """_write_code_snippet 函数测试."""

    def test_write_python_code(self):
        """测试 Python 代码保存为 input.py."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path, lang, diag = _write_code_snippet(root, PYTHON_SQL_CODE, None)
            assert file_path.name == "input.py"
            assert lang == "python"
            assert diag["auto_detected"] is True

    def test_write_javascript_code(self):
        """测试 JavaScript 代码保存为 input.js."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path, lang, diag = _write_code_snippet(root, JAVASCRIPT_XSS_CODE, None)
            assert file_path.name == "input.js"
            assert lang == "javascript"
            assert diag["auto_detected"] is True

    def test_write_java_code(self):
        """测试 Java 代码保存为 Vulnerable.java."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path, lang, diag = _write_code_snippet(root, JAVA_SQL_INJECTION_CODE, None)
            assert file_path.name == "Vulnerable.java"
            assert lang == "java"
            assert diag["auto_detected"] is True

    def test_write_c_code(self):
        """测试 C 代码保存为 input.c."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path, lang, diag = _write_code_snippet(root, C_BUFFER_OVERFLOW_CODE, None)
            assert file_path.name == "input.c"
            assert lang == "c"
            assert diag["auto_detected"] is True

    def test_language_hint_override(self):
        """测试 language_hint 覆盖自动检测."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 传入 Python 代码但指定 JavaScript
            file_path, lang, diag = _write_code_snippet(root, PYTHON_SQL_CODE, "javascript")
            assert file_path.name == "input.js"
            assert lang == "javascript"
            assert diag["auto_detected"] is False
            assert diag["language_hint"] == "javascript"

    def test_auto_hint_uses_detection(self):
        """测试 language_hint="auto" 时使用自动检测."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path, lang, diag = _write_code_snippet(root, JAVA_SQL_INJECTION_CODE, "auto")
            assert file_path.name == "Vulnerable.java"
            assert lang == "java"
            assert diag["auto_detected"] is True


class TestJavaScriptCodeSnippet:
    """JavaScript 代码片段检测测试."""

    def test_javascript_xss_detection(self):
        """测试 JavaScript XSS 代码片段能检测出 Cross-Site Scripting (XSS)."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVASCRIPT_XSS_CODE,
        )
        
        # 验证检测到 XSS
        types = [v["type"] for v in result["vulnerabilities"]]
        assert "Cross-Site Scripting (XSS)" in types, f"未检测到 XSS，实际类型: {types}"
        
        # 验证 language 字段是 JavaScript
        for v in result["vulnerabilities"]:
            if v["type"] == "Cross-Site Scripting (XSS)":
                assert v.get("language") == "JavaScript", f"language 字段错误: {v.get('language')}"
        
        # 验证 scanned_files 中是 input.js 而不是 input.py
        scanned_files = result.get("scanned_files", [])
        assert len(scanned_files) > 0
        assert scanned_files[0]["file"] == "input.js", f"文件名错误: {scanned_files[0]['file']}"
        
        # 验证 code_snippet_info
        assert "code_snippet_info" in result
        assert result["code_snippet_info"]["detected_language"] == "javascript"


class TestJavaCodeSnippet:
    """Java 代码片段检测测试."""

    def test_java_sql_injection_detection(self):
        """测试 Java SQL 注入代码片段能检测出 SQL Injection."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVA_SQL_INJECTION_CODE,
        )
        
        # 验证检测到 SQL Injection
        types = [v["type"] for v in result["vulnerabilities"]]
        assert "SQL Injection" in types, f"未检测到 SQL Injection，实际类型: {types}"
        
        # 验证 language 字段是 Java
        for v in result["vulnerabilities"]:
            if v["type"] == "SQL Injection":
                assert v.get("language") == "Java", f"language 字段错误: {v.get('language')}"
        
        # 验证 scanned_files 中是 Vulnerable.java
        scanned_files = result.get("scanned_files", [])
        assert len(scanned_files) > 0
        assert scanned_files[0]["file"] == "Vulnerable.java", f"文件名错误: {scanned_files[0]['file']}"
        
        # 验证 code_snippet_info
        assert "code_snippet_info" in result
        assert result["code_snippet_info"]["detected_language"] == "java"


class TestCCodeSnippet:
    """C 代码片段检测测试."""

    def test_c_buffer_overflow_detection(self):
        """测试 C strcpy 代码片段能检测出 Buffer Overflow."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=C_BUFFER_OVERFLOW_CODE,
        )
        
        # 验证检测到 Buffer Overflow
        types = [v["type"] for v in result["vulnerabilities"]]
        assert "Buffer Overflow" in types, f"未检测到 Buffer Overflow，实际类型: {types}"
        
        # 验证 language 字段是 C
        for v in result["vulnerabilities"]:
            if v["type"] == "Buffer Overflow":
                assert v.get("language") in ("C", "C/C++"), f"language 字段错误: {v.get('language')}"
        
        # 验证 scanned_files 中是 input.c
        scanned_files = result.get("scanned_files", [])
        assert len(scanned_files) > 0
        assert scanned_files[0]["file"] == "input.c", f"文件名错误: {scanned_files[0]['file']}"
        
        # 验证 code_snippet_info
        assert "code_snippet_info" in result
        assert result["code_snippet_info"]["detected_language"] == "c"


class TestPythonCodeSnippet:
    """Python 代码片段检测测试（确保原有功能不受影响）."""

    def test_python_sql_injection_detection(self):
        """测试 Python SQL 注入代码片段仍能检测."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=PYTHON_SQL_CODE,
        )
        
        # 验证检测到 SQL Injection
        types = [v["type"] for v in result["vulnerabilities"]]
        assert "SQL Injection" in types, f"未检测到 SQL Injection，实际类型: {types}"
        
        # 验证 language 字段是 Python
        for v in result["vulnerabilities"]:
            if v["type"] == "SQL Injection":
                assert v.get("language") == "Python", f"language 字段错误: {v.get('language')}"
        
        # 验证 scanned_files 中是 input.py
        scanned_files = result.get("scanned_files", [])
        assert len(scanned_files) > 0
        assert scanned_files[0]["file"] == "input.py", f"文件名错误: {scanned_files[0]['file']}"


class TestLanguageHint:
    """language_hint 参数测试."""

    def test_language_hint_javascript(self):
        """测试指定 language_hint="javascript" 时按 JavaScript 处理."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVASCRIPT_XSS_CODE,
            language_hint="javascript",
        )
        
        # 验证 code_snippet_info 显示使用了 hint
        assert result["code_snippet_info"]["language_hint"] == "javascript"
        assert result["code_snippet_info"]["auto_detected"] is False
        
        # 验证文件是 input.js
        scanned_files = result.get("scanned_files", [])
        assert scanned_files[0]["file"] == "input.js"

    def test_language_hint_java(self):
        """测试指定 language_hint="java" 时按 Java 处理."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVA_SQL_INJECTION_CODE,
            language_hint="java",
        )
        
        assert result["code_snippet_info"]["language_hint"] == "java"
        scanned_files = result.get("scanned_files", [])
        assert scanned_files[0]["file"] == "Vulnerable.java"


class TestScannedFilesDiagnostic:
    """扫描诊断信息测试."""

    def test_scanned_files_structure(self):
        """测试 scanned_files 包含预期的字段."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=PYTHON_SQL_CODE,
        )
        
        scanned_files = result.get("scanned_files", [])
        assert len(scanned_files) > 0
        
        file_record = scanned_files[0]
        required_fields = ["file", "detected_language", "detector", "finding_count", "status"]
        for field in required_fields:
            assert field in file_record, f"缺少字段: {field}"
        
        assert file_record["status"] == "completed"
        assert file_record["detector"] == "LanguageRouter"


class TestNonPythonNotSavedAsInputPy:
    """验证非 Python 代码不再被保存为 input.py."""

    def test_javascript_not_input_py(self):
        """JavaScript 代码不应保存为 input.py."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVASCRIPT_XSS_CODE,
        )
        scanned_files = result.get("scanned_files", [])
        for f in scanned_files:
            assert not f["file"].endswith("input.py"), "错误地保存为 input.py"

    def test_java_not_input_py(self):
        """Java 代码不应保存为 input.py."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=JAVA_SQL_INJECTION_CODE,
        )
        scanned_files = result.get("scanned_files", [])
        for f in scanned_files:
            assert not f["file"].endswith("input.py"), "错误地保存为 input.py"

    def test_c_not_input_py(self):
        """C 代码不应保存为 input.py."""
        result = analyze_input(
            input_type="code",
            ai_mode="rule",
            code=C_BUFFER_OVERFLOW_CODE,
        )
        scanned_files = result.get("scanned_files", [])
        for f in scanned_files:
            assert not f["file"].endswith("input.py"), "错误地保存为 input.py"
