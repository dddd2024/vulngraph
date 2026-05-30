from analysis_engine import analyze_input


F_STRING_SQL_LOGIN_CODE = (
    "import pymysql\n"
    "db = pymysql.connect(host='localhost', user='root', password='123456')\n"
    "cursor = db.cursor()\n"
    "username = input('请输入用户名：')\n"
    "password = input('请输入密码：')\n"
    "sql = f\"SELECT * FROM user WHERE username='{username}' AND password='{password}'\"\n"
    "cursor.execute(sql)\n"
)


def test_analyze_input_rule_mode_outputs_vulnerability():
    code = (
        "def search_user(name):\n"
        "    sql = \"SELECT * FROM users WHERE name='\" + name + \"'\"\n"
        "    return conn.execute(sql)\n"
    )
    result = analyze_input(input_type="code", code=code)

    assert result["languages"] == ["zh-CN", "en-US"]
    assert result["analysis_mode"] == "detect-only"
    assert result["vulnerabilities"]
    finding = result["vulnerabilities"][0]
    assert finding["type"] == "SQL Injection"
    assert finding["bilingual"]["type"]["en"] == "SQL Injection"
    assert finding["bilingual"]["type"]["zh"] == "SQL 注入"
    assert result["display"]["zh"]["vulnerabilities"]
    assert result["display"]["zh"]["vulnerabilities"][0]["漏洞类型"] == "SQL 注入"


def test_analyze_input_no_vulnerability_outputs_chinese_message():
    code = "def hello(name):\n    return f'hello {name}'\n"
    result = analyze_input(input_type="code", code=code)

    assert result["count"] == 0
    assert result["vulnerabilities"] == []
    assert result["skipped_files"] == []
    assert result["display"]["zh"]["message"] == "未检测到漏洞。"


def test_analyze_input_invalid_python_outputs_skip_details():
    result = analyze_input(input_type="code", code="def broken(:\n")

    assert result["count"] == 0
    assert result["skipped_files"] == ["input.py"]
    assert result["skipped_details"]
    assert result["skipped_details"][0]["file"] == "input.py"
    assert "Code parsing failed" in result["skipped_details"][0]["reason_en"]
    assert "代码解析失败" in result["skipped_details"][0]["reason_zh"]
    assert result["display"]["zh"]["skipped_files"]
    assert "代码解析失败" in result["display"]["zh"]["skipped_files"][0]["原因"]


def test_analyze_input_rule_mode_detects_f_string_sql_login():
    result = analyze_input(
        input_type="code",
        code=F_STRING_SQL_LOGIN_CODE,
    )

    assert result["count"] == 1
    assert result["vulnerabilities"][0]["type"] == "SQL Injection"
    assert result["vulnerabilities"][0]["bilingual"]["type"]["zh"] == "SQL 注入"
    assert result["display"]["zh"]["vulnerabilities"][0]["漏洞类型"] == "SQL 注入"


def test_analyze_input_outputs_risk_score():
    code = (
        "def search_user(name):\n"
        "    sql = \"SELECT * FROM users WHERE name='\" + name + \"'\"\n"
        "    return conn.execute(sql)\n"
    )
    result = analyze_input(input_type="code", code=code)

    assert result["vulnerabilities"]
    finding = result["vulnerabilities"][0]
    assert "risk_score" in finding
    assert finding["risk_score"] > 0
    assert "cwe" in finding
    assert "confidence" in finding
