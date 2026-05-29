"""污点分析引擎测试.

测试用例：
1. request.args.get → f-string SQL → cursor.execute 报 SQL Injection
2. cursor.execute(sql, params) 不报 SQL Injection
3. request.args.get → open(path) 报 Path Traversal
4. secure_filename 后进入 open 不报或降低置信度
5. request.args.get → os.system 报 Command Injection
6. subprocess.run(["cmd", user_input], shell=False) 不报 Command Injection
7. subprocess.run(cmd, shell=True) 报 Command Injection
8. os.path.join 单独出现不报 Path Traversal
9. template.execute(user_input) 不应报 SQL Injection
10. 参数化 SQL 使用 name 后，name 再进入危险 f-string SQL 时仍应报 SQL Injection
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from detector.core.rule_loader import load_yaml_rules
from detector.engines.taint_engine import TaintEngine
from detector.core.runner import DetectorRunner
from analysis_engine import analyze_input


# ---------------------------------------------------------------------------
# 测试 fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def taint_engine() -> TaintEngine:
    """创建污点分析引擎."""
    return TaintEngine()


@pytest.fixture
def taint_rules() -> list:
    """加载污点分析规则."""
    rules = load_yaml_rules()
    return [r for r in rules if r.engine == "taint"]


def _write_temp_file(content: str) -> str:
    """写入临时文件并返回路径."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(content)
        return f.name


# ---------------------------------------------------------------------------
# SQL Injection 测试
# ---------------------------------------------------------------------------

def test_sql_injection_fstring(taint_engine: TaintEngine, taint_rules: list):
    """测试 request.args.get → f-string SQL → cursor.execute 报 SQL Injection."""
    code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE name='{name}'"
    cursor.execute(sql)
    return cursor.fetchall()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 SQL Injection
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) > 0
        
        # 检查 finding 字段
        finding = sql_findings[0]
        assert finding.engine == "taint"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"
        assert finding.cwe == "CWE-89"
        
        # 检查污点追踪
        assert finding.source == "request.args.get"
        assert finding.sink == "cursor.execute"
        assert len(finding.taint_trace) > 0
        
        # 检查 metadata
        finding_dict = finding.to_dict()
        assert "metadata" in finding_dict
        assert "taint_trace" in finding_dict["metadata"]
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_sql_injection_safe_params(taint_engine: TaintEngine, taint_rules: list):
    """测试 cursor.execute(sql, params) 不报 SQL Injection."""
    code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE name=?"
    cursor.execute(sql, (name,))
    return cursor.fetchall()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 使用参数化查询，不应该报 SQL Injection
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_sql_injection_string_concat(taint_engine: TaintEngine, taint_rules: list):
    """测试字符串拼接 SQL 注入."""
    code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE name='" + name + "'"
    cursor.execute(sql)
    return cursor.fetchall()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 SQL Injection
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) > 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_sql_injection_after_safe_params_still_vulnerable(taint_engine: TaintEngine, taint_rules: list):
    """测试参数化 SQL 后 name 再进入危险 f-string SQL 仍应报 SQL Injection."""
    code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # 第一次使用参数化查询（安全）
    cursor.execute("SELECT * FROM users WHERE name=?", (name,))
    # 第二次使用 f-string（危险）
    sql = f"SELECT * FROM admins WHERE name='{name}'"
    cursor.execute(sql)
    return cursor.fetchall()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 SQL Injection（第二次调用）
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) > 0
        # 确保是第二次调用（f-string 那次）
        lines = [f.line for f in sql_findings]
        assert any(l > 12 for l in lines)  # 第二次 execute 在行 13
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_sql_injection_false_positive_template_execute(taint_engine: TaintEngine, taint_rules: list):
    """测试误报：template.execute(user_input) 不应报 SQL Injection."""
    code = '''
from flask import Flask, request

class Template:
    def execute(self, code):
        # 这不是 SQL 执行
        return eval(code)

app = Flask(__name__)
template = Template()

@app.route("/run")
def run():
    user_input = request.args.get("code")
    result = template.execute(user_input)
    return str(result)
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # template.execute 不是 SQL sink，不应该报 SQL Injection
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Inline Source → Sink 测试
# ---------------------------------------------------------------------------

def test_inline_source_to_os_system_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 inline source → sink: os.system(request.args.get("cmd")) 报 Command Injection."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_command():
    os.system(request.args.get("cmd"))
    return "done"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        assert len(cmd_findings) > 0
        
        # 检查 source 和 sink
        finding = cmd_findings[0]
        assert finding.source == "request.args.get"
        assert finding.sink == "os.system"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_inline_source_to_open_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 inline source → sink: open(request.args.get("path")) 报 Path Traversal."""
    code = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/read")
def read_file():
    return open(request.args.get("path")).read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 source 和 sink
        finding = pt_findings[0]
        assert finding.source == "request.args.get"
        assert finding.sink == "open"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_inline_source_to_cursor_execute_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 inline source → sink: cursor.execute(f"...{request.args.get('name')}...") 报 SQL Injection."""
    code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name='{request.args.get('name')}'")
    return cursor.fetchall()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 SQL Injection
        sql_findings = [f for f in findings if f.type == "SQL Injection"]
        assert len(sql_findings) > 0
        
        # 检查 source 和 sink
        finding = sql_findings[0]
        assert finding.source == "request.args.get"
        assert finding.sink == "cursor.execute"
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Path Traversal 测试
# ---------------------------------------------------------------------------

def test_path_traversal_open(taint_engine: TaintEngine, taint_rules: list):
    """测试 request.args.get → open(path) 报 Path Traversal."""
    code = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    with open(path, "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 finding 字段
        finding = pt_findings[0]
        assert finding.engine == "taint"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"
        assert finding.cwe == "CWE-22"
        
        # 检查污点追踪
        assert finding.source == "request.args.get"
        assert finding.sink == "open"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_traversal_with_secure_filename(taint_engine: TaintEngine, taint_rules: list):
    """测试 secure_filename 后进入 open 不报或降低置信度."""
    code = '''
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route("/read")
def read_file():
    filename = request.args.get("filename")
    safe_name = secure_filename(filename)
    with open(safe_name, "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 使用 secure_filename，不应该报 Path Traversal
        # 或者置信度降低
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        # 当前实现应该不报漏洞（净化器检测）
        assert len(pt_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_traversal_pathlib(taint_engine: TaintEngine, taint_rules: list):
    """测试 pathlib Path.read_text 路径穿越."""
    code = '''
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    p = Path(path)
    return p.read_text()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_open_receiver_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 Path.open() receiver 检查：p.open() 当 p 被污染时报 Path Traversal."""
    code = '''
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    p = Path(path)
    with p.open() as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 sink 是 Path.open
        finding = pt_findings[0]
        assert "open" in finding.sink
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_read_text_direct_constructor_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 Path 直接构造函数 receiver 检查：Path(path).read_text() 报 Path Traversal."""
    code = '''
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

@app.route("/read")
def read_file():
    return Path(request.args.get("path")).read_text()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 sink 是 Path.read_text
        finding = pt_findings[0]
        assert "read_text" in finding.sink
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_traversal_os_path_join_alone_no_vuln(taint_engine: TaintEngine, taint_rules: list):
    """测试误报：os.path.join(base, user_input) 单独出现不应报 Path Traversal."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/join")
def join_path():
    base = "/safe/base"
    user_input = request.args.get("path")
    result = os.path.join(base, user_input)
    return result
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # os.path.join 是 propagator，单独使用不报漏洞
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_traversal_os_path_join_to_open(taint_engine: TaintEngine, taint_rules: list):
    """测试 os.path.join 结果流入 open 时报 Path Traversal."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/read")
def read_file():
    base = "/safe/base"
    user_input = request.args.get("path")
    full_path = os.path.join(base, user_input)
    with open(full_path, "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # os.path.join 结果流入 open，应该报 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_os_path_join_user_input_at_third_arg_propagates(taint_engine: TaintEngine, taint_rules: list):
    """测试 os.path.join 第三个参数被污染时也能传播到 sink."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/read")
def read_file():
    base = "/safe/base"
    middle = "middle"
    user_input = request.args.get("path")
    full_path = os.path.join(base, middle, user_input)  # 第三个参数被污染
    with open(full_path, "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 第三个参数被污染，join 结果流入 open，应该报 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Command Injection 测试
# ---------------------------------------------------------------------------

def test_command_injection_os_system(taint_engine: TaintEngine, taint_rules: list):
    """测试 request.args.get → os.system 报 Command Injection."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "done"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        assert len(cmd_findings) > 0
        
        # 检查 finding 字段
        finding = cmd_findings[0]
        assert finding.engine == "taint"
        assert finding.severity == "ERROR"
        assert finding.confidence == "high"
        assert finding.cwe == "CWE-78"
        
        # 检查污点追踪
        assert finding.source == "request.args.get"
        assert finding.sink == "os.system"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_command_injection_safe_subprocess(taint_engine: TaintEngine, taint_rules: list):
    """测试 subprocess.run(["cmd", user_input], shell=False) 不报 Command Injection."""
    code = '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_command():
    user_input = request.args.get("input")
    result = subprocess.run(["echo", user_input], shell=False, capture_output=True)
    return result.stdout.decode()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # shell=False 且使用列表参数，不应该报 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        assert len(cmd_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_subprocess_list_without_shell_keyword_safe(taint_engine: TaintEngine, taint_rules: list):
    """测试 subprocess.run(["cmd", user_input]) 没有 shell 关键字时不报 Command Injection."""
    code = '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_command():
    user_input = request.args.get("input")
    result = subprocess.run(["echo", user_input], capture_output=True)
    return result.stdout.decode()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 没有 shell 关键字（默认 False）且使用列表参数，不应该报 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        assert len(cmd_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_command_injection_subprocess_shell_true(taint_engine: TaintEngine, taint_rules: list):
    """测试 subprocess.run(cmd, shell=True) 报 Command Injection."""
    code = '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # shell=True，应该检测到 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        # 污点引擎会检测，因为 cmd 参数被污染
        assert len(cmd_findings) > 0
        
        finding = cmd_findings[0]
        assert finding.source == "request.args.get"
        assert finding.sink == "subprocess.run"
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 多输入源测试
# ---------------------------------------------------------------------------

def test_multiple_sources(taint_engine: TaintEngine, taint_rules: list):
    """测试多种输入源."""
    code = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/form")
def form_handler():
    # POST 表单输入
    username = request.form.get("username")
    # JSON 输入
    data = request.get_json()
    email = data.get("email") if data else ""
    return f"{username}: {email}"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 检查是否能识别 request.form.get 和 request.get_json
        # 这个代码没有 sink，所以不应该有漏洞
        assert len(findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Finding 格式兼容性测试
# ---------------------------------------------------------------------------

def test_finding_format_compatibility(taint_engine: TaintEngine, taint_rules: list):
    """测试 TaintFinding.to_dict() 输出兼容现有 finding 格式."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "done"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        if findings:
            finding_dict = findings[0].to_dict()
            
            # 检查必需字段
            assert "type" in finding_dict
            assert "file" in finding_dict
            assert "line" in finding_dict
            assert "severity" in finding_dict
            assert "engine" in finding_dict
            assert "confidence" in finding_dict
            
            # 检查 engine 字段
            assert finding_dict["engine"] == "taint"
            
            # 检查 metadata 字段
            assert "metadata" in finding_dict
            metadata = finding_dict["metadata"]
            assert "taint_trace" in metadata
            assert "source" in metadata
            assert "sink" in metadata
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 边界情况测试
# ---------------------------------------------------------------------------

def test_no_vulnerability_safe_code(taint_engine: TaintEngine, taint_rules: list):
    """测试安全代码不报漏洞."""
    code = '''
from flask import Flask

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = "world"  # 硬编码，不是污点源
    return f"Hello, {name}!"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        assert len(findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_no_python_file(taint_engine: TaintEngine, taint_rules: list):
    """测试非 Python 文件不处理."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("not python code")
        file_path = f.name
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        assert len(findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_syntax_error_file(taint_engine: TaintEngine, taint_rules: list):
    """测试语法错误文件不报漏洞."""
    code = '''
def broken():
    # 语法错误
    return "missing closing quote
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        assert len(findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 规则加载测试
# ---------------------------------------------------------------------------

def test_taint_rules_loaded():
    """测试污点规则是否正确加载."""
    rules = load_yaml_rules()
    taint_rules = [r for r in rules if r.engine == "taint"]
    
    # 应该至少有 3 条污点规则
    assert len(taint_rules) >= 3
    
    # 检查规则 ID
    rule_ids = [r.id for r in taint_rules]
    assert "TAINT-SQL-001" in rule_ids
    assert "TAINT-PT-001" in rule_ids
    assert "TAINT-CMD-001" in rule_ids
    
    # 检查规则 pattern 包含污点配置
    for rule in taint_rules:
        assert "sources" in rule.pattern
        assert "sinks" in rule.pattern
        assert len(rule.pattern["sources"]) > 0
        assert len(rule.pattern["sinks"]) > 0


# ---------------------------------------------------------------------------
# 集成测试 - DetectorRunner 级别
# ---------------------------------------------------------------------------

def test_detector_runner_integration():
    """测试 DetectorRunner 级别集成，确认 engines 包含 taint."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "done"
'''
    file_path = _write_temp_file(code)
    try:
        runner = DetectorRunner()
        findings = runner.scan_file(file_path)
        
        # 查找 Command Injection
        cmd_findings = [f for f in findings if f.get("type") == "Command Injection"]
        assert len(cmd_findings) > 0
        
        # 检查至少有一个 finding 的 engines 包含 taint
        taint_findings = [f for f in cmd_findings if "taint" in f.get("engines", [])]
        assert len(taint_findings) > 0, "没有找到 taint 引擎的 finding"
        
        # 检查 taint finding 的 metadata 包含 taint_trace
        for finding in taint_findings:
            metadata = finding.get("metadata", {})
            assert "taint_trace" in metadata
            assert len(metadata["taint_trace"]) > 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 集成测试 - analyze_input 级别
# ---------------------------------------------------------------------------

def test_analyze_input_integration():
    """测试 analyze_input 级别集成，确认最终 JSON 包含 taint 引擎和 taint_trace."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "done"
'''
    result = analyze_input(
        input_type="code",
        ai_mode="rule",
        code=code,
    )
    
    # 检查是否有漏洞
    vulnerabilities = result.get("vulnerabilities", [])
    cmd_vulns = [v for v in vulnerabilities if v.get("type") == "Command Injection"]
    
    # 应该检测到 Command Injection
    assert len(cmd_vulns) > 0
    
    # 检查至少有一个 vulnerability 的 engines 包含 taint
    taint_vulns = []
    for vuln in cmd_vulns:
        engines = vuln.get("engines", [])
        engine_names = [e.get("en") if isinstance(e, dict) else e for e in engines]
        if "taint" in engine_names or any("taint" in str(e) for e in engines):
            taint_vulns.append(vuln)
    
    assert len(taint_vulns) > 0, "没有找到 taint 引擎的 vulnerability"
    
    # 检查 taint vulnerability 的 metadata 包含 taint_trace
    for vuln in taint_vulns:
        metadata = vuln.get("metadata", {})
        assert "taint_trace" in metadata, f"metadata 中缺少 taint_trace: {metadata.keys()}"
        assert len(metadata["taint_trace"]) > 0


# ---------------------------------------------------------------------------
# Boundary Check Sanitizer 测试
# ---------------------------------------------------------------------------

def test_os_path_realpath_propagates_to_open_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 os.path.realpath 传播污点到 open 时报 Path Traversal."""
    code = '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    real = os.path.realpath(path)
    with open(real, "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # os.path.realpath 是 propagator，污点传播到 open，应该报 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 source 和 sink
        finding = pt_findings[0]
        assert finding.source == "request.args.get"
        assert finding.sink == "open"
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_path_resolve_propagates_to_read_text_reports(taint_engine: TaintEngine, taint_rules: list):
    """测试 Path.resolve 传播污点到 read_text 时报 Path Traversal."""
    code = '''
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    p = Path(path)
    resolved = p.resolve()
    return resolved.read_text()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # Path.resolve 是 propagator，污点传播到 read_text，应该报 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 source 和 sink
        finding = pt_findings[0]
        assert finding.source == "request.args.get"
        assert "read_text" in finding.sink
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Inline Sanitizer 测试
# ---------------------------------------------------------------------------

def test_inline_sanitizer_secure_filename_no_vuln(taint_engine: TaintEngine, taint_rules: list):
    """测试 inline sanitizer: open(secure_filename(request.args.get("path"))) 不报 Path Traversal."""
    code = '''
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route("/read")
def read_file():
    with open(secure_filename(request.args.get("path")), "r") as f:
        return f.read()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # secure_filename 是 sanitizer，包裹 inline source，不应报 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


def test_inline_sanitizer_shlex_quote_no_vuln(taint_engine: TaintEngine, taint_rules: list):
    """测试 inline sanitizer: os.system("ls " + shlex.quote(user_input)) 不报 Command Injection."""
    code = '''
from flask import Flask, request
import os
import shlex

app = Flask(__name__)

@app.route("/run")
def run_command():
    name = request.args.get("name")
    os.system("ls " + shlex.quote(name))
    return "done"
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # shlex.quote 是 sanitizer，包裹 inline source，不应报 Command Injection
        cmd_findings = [f for f in findings if f.type == "Command Injection"]
        assert len(cmd_findings) == 0
    finally:
        Path(file_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Inline Source Trace 测试
# ---------------------------------------------------------------------------

def test_inline_source_trace_correct_source_name(taint_engine: TaintEngine, taint_rules: list):
    """测试 Path(request.args.get("path")).read_text() 的 finding.source 正确显示 request.args.get."""
    code = '''
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)

@app.route("/read")
def read_file():
    return Path(request.args.get("path")).read_text()
'''
    file_path = _write_temp_file(code)
    try:
        findings = taint_engine.scan_file(file_path, taint_rules)
        
        # 应该检测到 Path Traversal
        pt_findings = [f for f in findings if f.type == "Path Traversal"]
        assert len(pt_findings) > 0
        
        # 检查 source 正确显示为 request.args.get
        finding = pt_findings[0]
        assert finding.source == "request.args.get"
        
        # 检查 sink 是 Path.read_text
        assert "read_text" in finding.sink
        
        # 检查 metadata 中的 source 也正确
        finding_dict = finding.to_dict()
        metadata = finding_dict.get("metadata", {})
        assert metadata.get("source") == "request.args.get"
    finally:
        Path(file_path).unlink(missing_ok=True)