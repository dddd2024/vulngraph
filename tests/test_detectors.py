from pathlib import Path

from detector.vuln_detector import (
    detect_path_traversal,
    detect_privilege_escalation,
    detect_sql_injection,
)


def test_sql_injection_detector_flags_string_concat(tmp_path: Path):
    file_path = tmp_path / "vuln.py"
    file_path.write_text(
        "def f(name):\n"
        "    sql = \"SELECT * FROM users WHERE name='\" + name + \"'\"\n"
        "    return conn.execute(sql)\n",
        encoding="utf-8",
    )
    findings = detect_sql_injection(str(file_path))
    assert findings
    assert findings[0]["type"] == "SQL Injection"


def test_sql_injection_detector_flags_f_string_assigned_then_executed(tmp_path: Path):
    file_path = tmp_path / "vuln.py"
    file_path.write_text(
        "import pymysql\n"
        "db = pymysql.connect(host='localhost')\n"
        "cursor = db.cursor()\n"
        "username = input('请输入用户名：')\n"
        "password = input('请输入密码：')\n"
        "sql = f\"SELECT * FROM user WHERE username='{username}' AND password='{password}'\"\n"
        "cursor.execute(sql)\n",
        encoding="utf-8",
    )
    findings = detect_sql_injection(str(file_path))
    assert findings
    assert findings[0]["type"] == "SQL Injection"


def test_sql_injection_detector_flags_percent_and_format_sql(tmp_path: Path):
    percent_path = tmp_path / "percent.py"
    percent_path.write_text(
        "def f(name):\n"
        "    sql = \"SELECT * FROM users WHERE name='%s'\" % name\n"
        "    cursor.execute(sql)\n",
        encoding="utf-8",
    )
    format_path = tmp_path / "format.py"
    format_path.write_text(
        "def f(name):\n"
        "    sql = \"SELECT * FROM users WHERE name='{}'\".format(name)\n"
        "    cursor.execute(sql)\n",
        encoding="utf-8",
    )

    assert detect_sql_injection(str(percent_path))
    assert detect_sql_injection(str(format_path))


def test_sql_injection_detector_ignores_parameterized_query(tmp_path: Path):
    file_path = tmp_path / "safe.py"
    file_path.write_text(
        "def f(username, password):\n"
        "    sql = \"SELECT * FROM user WHERE username=%s AND password=%s\"\n"
        "    cursor.execute(sql, (username, password))\n",
        encoding="utf-8",
    )
    assert detect_sql_injection(str(file_path)) == []


def test_path_traversal_detector_flags_open_name_arg(tmp_path: Path):
    file_path = tmp_path / "vuln.py"
    file_path.write_text(
        "def read_file(path):\n"
        "    with open(path, 'r') as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )
    findings = detect_path_traversal(str(file_path))
    assert findings
    assert findings[0]["type"] == "Path Traversal"


def test_privilege_detector_flags_admin_route_without_auth(tmp_path: Path):
    file_path = tmp_path / "vuln.py"
    file_path.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/admin/delete')\n"
        "def delete_user():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    findings = detect_privilege_escalation(str(file_path))
    assert findings
    assert findings[0]["type"] == "Privilege Escalation"

