"""User-related business logic.

This service sits between the route handlers and the data layer. It forwards
tainted request data into the SQL sink in `db.raw_query`, forming a multi-hop
cross-file taint flow: routes/users.py -> user_service.py -> db.py.
"""
from typing import Any

from .. import db
from .crypto_utils import hash_password


def find_user_by_id(user_id: str) -> list[dict[str, Any]]:
    # CWE-89: user_id is concatenated straight into SQL and passed to the sink.
    sql = f"SELECT id, username, email FROM users WHERE id = {user_id};"
    return db.raw_query(sql)


def search_users(name: str) -> list[dict[str, Any]]:
    # CWE-89: classic string-built LIKE filter.
    sql = "SELECT id, username FROM users WHERE username LIKE '%" + name + "%';"
    return db.raw_query(sql)


def create_user(username: str, password: str, email: str) -> None:
    pw = hash_password(password)  # weak hash flows into the stored row
    # CWE-89: all three values interpolated into the INSERT.
    sql = (
        "INSERT INTO users (username, password, email) VALUES "
        f"('{username}', '{pw}', '{email}');"
    )
    db.raw_query(sql)


def get_user_safe(user_id: str) -> dict[str, Any] | None:
    """Control sample: parameterized query (should NOT be flagged)."""
    return db.query_one("SELECT id, username FROM users WHERE id = ?", [user_id])
