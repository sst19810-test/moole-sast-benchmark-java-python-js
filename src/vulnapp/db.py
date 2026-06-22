"""Thin SQLite data-access layer.

The query helpers here are deliberately unsafe so that taint flowing from the
web layer into these sinks can be exercised end to end (cross-file taint).
"""
import sqlite3
from typing import Any, Iterable

from .config import Config


def _connect() -> sqlite3.Connection:
    # Using a file DB derived from config; connection itself is not the issue.
    path = Config.DATABASE_URL.replace("sqlite:///", "")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def raw_query(sql: str) -> list[dict[str, Any]]:
    """Execute an already-assembled SQL string. SINK (CWE-89).

    Callers frequently build `sql` via f-strings with request data, so this is
    the terminal sink for SQL-injection taint flows.
    """
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.executescript(sql)  # executescript allows stacked queries -> worse
        rows = cur.fetchall() if cur.description else []
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_one(sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
    """Parameterized helper (safe control sample; should NOT be flagged)."""
    conn = _connect()
    try:
        cur = conn.execute(sql, tuple(params))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
