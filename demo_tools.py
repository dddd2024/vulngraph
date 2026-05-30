import subprocess
import sys
from pathlib import Path
from typing import Any

VULNERABLE_DB_PY = """import sqlite3

conn = sqlite3.connect("users.db", check_same_thread=False)


def bootstrap_db() -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)"
    )
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.execute("INSERT INTO users(name, role) VALUES ('admin', 'admin')")
        conn.execute("INSERT INTO users(name, role) VALUES ('alice', 'user')")
        conn.execute("INSERT INTO users(name, role) VALUES ('bob', 'user')")
        conn.commit()


def search_user(name: str) -> str:
    sql = "SELECT * FROM users WHERE name='" + name + "'"
    cursor = conn.execute(sql)
    return str(cursor.fetchall())
"""


def reset_demo_state(project_root: str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    removed: list[str] = []

    for rel in ["pipeline_result.json", "users.db"]:
        path = root / rel
        if path.exists():
            path.unlink()
            removed.append(str(path))

    db_path = root / "repo" / "db.py"
    db_path.write_text(VULNERABLE_DB_PY, encoding="utf-8")

    return {"status": "ok", "removed": removed, "restored": str(db_path)}


def run_demo_tests(project_root: str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    # 运行检测回归测试
    target = "tests"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", target, "-q"],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    return {
        "success": proc.returncode == 0,
        "target": target,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }
