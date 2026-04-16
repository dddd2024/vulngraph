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

