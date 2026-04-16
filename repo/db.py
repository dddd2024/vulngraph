import sqlite3

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
    sql = "SELECT * FROM users WHERE name=?"
    cursor = conn.execute(sql, (name,))
    return str(cursor.fetchall())
