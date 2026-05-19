import difflib
from pathlib import Path
from typing import Any

from llm.client import LLMClient
from patch.generate_test import generate_sql_injection_test


def _to_unified_diff(original: str, updated: str, relative_path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
        )
    )


def _deterministic_sql_patch(repo_root: str) -> dict[str, str]:
    file_path = Path(repo_root) / "repo" / "db.py"
    original = file_path.read_text(encoding="utf-8")
    updated = original.replace(
        'sql = "SELECT * FROM users WHERE name=\'" + name + "\'"\n    cursor = conn.execute(sql)',
        'sql = "SELECT * FROM users WHERE name=?"\n    cursor = conn.execute(sql, (name,))',
    )
    if original == updated:
        raise RuntimeError("Expected vulnerable SQL pattern not found in repo/db.py")
    patch = _to_unified_diff(original, updated, "repo/db.py")
    return {
        "reason": "Use parameterized query to block SQL injection.",
        "patch": patch,
        "test": generate_sql_injection_test(),
    }


def _llm_generate(prompt: str, model: str | None = None) -> dict[str, str]:
    client = LLMClient(ai_mode="cloud", model_name=model)
    return client.generate_patch_json(prompt)


def generate_patch(vuln: dict[str, Any], prompt: str, repo_root: str) -> dict[str, str]:
    if vuln["type"] == "SQL Injection":
        return _deterministic_sql_patch(repo_root)
    return _llm_generate(prompt)

