from pathlib import Path

from detector.vuln_detector import (
    detect_all,
    detect_command_injection,
    detect_dangerous_code_execution,
    detect_debug_mode,
    detect_hardcoded_secret,
    detect_insecure_tls,
    detect_unsafe_deserialization,
    detect_weak_crypto,
)


def _write_tmp(tmp_path: Path, source: str) -> str:
    file_path = tmp_path / "vuln.py"
    file_path.write_text(source, encoding="utf-8")
    return str(file_path)


def test_dangerous_code_execution_flags_eval(tmp_path: Path):
    file_path = _write_tmp(tmp_path, "def f(expr):\n    return eval(expr)\n")

    findings = detect_dangerous_code_execution(file_path)

    assert findings
    assert findings[0]["type"] == "Dangerous Code Execution"
    assert findings[0]["symbol"] == "eval"
    assert findings[0]["severity"] == "ERROR"


def test_command_injection_flags_subprocess_shell_true(tmp_path: Path):
    file_path = _write_tmp(
        tmp_path,
        "import subprocess\n"
        "def f(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
    )

    findings = detect_command_injection(file_path)

    assert findings
    assert findings[0]["type"] == "Command Injection"
    assert findings[0]["symbol"] == "subprocess.run"


def test_unsafe_deserialization_flags_yaml_load_without_safeloader(tmp_path: Path):
    file_path = _write_tmp(
        tmp_path,
        "import yaml\n"
        "def f(data):\n"
        "    return yaml.load(data)\n",
    )

    findings = detect_unsafe_deserialization(file_path)

    assert findings
    assert findings[0]["type"] == "Unsafe Deserialization"
    assert findings[0]["symbol"] == "yaml.load"


def test_hardcoded_secret_flags_non_empty_string_assignment(tmp_path: Path):
    file_path = _write_tmp(tmp_path, 'api_key = "abc123"\n')

    findings = detect_hardcoded_secret(file_path)

    assert findings
    assert findings[0]["type"] == "Hardcoded Secret"
    assert findings[0]["symbol"] == "api_key"
    assert findings[0]["severity"] == "WARNING"


def test_weak_crypto_flags_hashlib_md5(tmp_path: Path):
    file_path = _write_tmp(
        tmp_path,
        "import hashlib\n"
        "digest = hashlib.md5(b'data').hexdigest()\n",
    )

    findings = detect_weak_crypto(file_path)

    assert findings
    assert findings[0]["type"] == "Weak Cryptography"
    assert findings[0]["symbol"] == "hashlib.md5"


def test_debug_mode_flags_app_run_debug_true(tmp_path: Path):
    file_path = _write_tmp(tmp_path, "app.run(debug=True)\n")

    findings = detect_debug_mode(file_path)

    assert findings
    assert findings[0]["type"] == "Debug Mode Enabled"


def test_insecure_tls_flags_requests_verify_false(tmp_path: Path):
    file_path = _write_tmp(
        tmp_path,
        "import requests\n"
        "requests.get('https://example.test', verify=False)\n",
    )

    findings = detect_insecure_tls(file_path)

    assert findings
    assert findings[0]["type"] == "Insecure TLS Verification"
    assert findings[0]["symbol"] == "requests.get"


def test_detect_all_includes_new_ast_rules(tmp_path: Path):
    file_path = tmp_path / "vuln.py"
    file_path.write_text("import os\nos.system('id')\nDEBUG = True\n", encoding="utf-8")

    types = {finding["type"] for finding in detect_all(str(tmp_path))}

    assert "Command Injection" in types
    assert "Debug Mode Enabled" in types
