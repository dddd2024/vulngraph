from pathlib import Path

from patch.generate_patch import generate_patch


def test_generate_patch_sql_injection_uses_deterministic_patch(monkeypatch, tmp_path):
    def fail_if_instantiated(*args, **kwargs):
        raise AssertionError("LLMClient must not be used for SQL Injection patches")

    monkeypatch.setattr("patch.generate_patch.LLMClient", fail_if_instantiated)
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "db.py").write_text(
        'def search_user(name):\n'
        '    sql = "SELECT * FROM users WHERE name=\'" + name + "\'"\n'
        "    cursor = conn.execute(sql)\n",
        encoding="utf-8",
    )

    result = generate_patch({"type": "SQL Injection"}, "prompt", str(tmp_path))

    assert "parameterized query" in result["reason"]
    assert "repo/db.py" in result["patch"]
    assert result["test"]
