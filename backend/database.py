"""
SQLite persistence layer for domain monitors.
Each row = one (domain, email) watch subscription.
"""
import os
import sqlite3

DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "monitors.db"),
)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitors (
            id          TEXT PRIMARY KEY,
            domain      TEXT NOT NULL,
            email       TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_checked TEXT,
            snapshot    TEXT,
            UNIQUE(domain, email)
        )
    """)
    conn.commit()
    conn.close()
