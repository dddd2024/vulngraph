from repo import db


def test_sql_injection_blocked():
    db.bootstrap_db()
    payload = "' OR 1=1 --"
    result = db.search_user(payload)
    assert "admin" not in result
