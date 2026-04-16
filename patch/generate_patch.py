import difflib
import json
import os
from pathlib import Path
from typing import Any

from patch.generate_test import generate_sql_injection_test

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - optional runtime dependency
    OpenAI = None  # type: ignore[assignment]


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


def _llm_generate(prompt: str, model: str = "gpt-4.1") -> dict[str, str]:
    if OpenAI is None:
        raise RuntimeError("openai package is unavailable.")
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set.")
    client = OpenAI()
    resp = client.chat.completions.create(
        model=model, messages=[{"role": "user", "content": prompt}]
    )
    content = (resp.choices[0].message.content or "").strip()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM response is not valid JSON: {content[:300]}") from exc
    for key in ("reason", "patch", "test"):
        if key not in data:
            raise RuntimeError(f"LLM JSON missing required key: {key}")
    return {
        "reason": str(data["reason"]),
        "patch": str(data["patch"]),
        "test": str(data["test"]),
    }


def generate_patch(vuln: dict[str, Any], prompt: str, repo_root: str) -> dict[str, str]:
    if vuln["type"] == "SQL Injection":
        return _deterministic_sql_patch(repo_root)
    return _llm_generate(prompt)

