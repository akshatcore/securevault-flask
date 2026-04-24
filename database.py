"""
database.py — SQLite data access layer
=======================================
Schema
------
users       — registered accounts (hashed passwords, roles)
files       — metadata for every uploaded file
login_log   — audit trail for every login attempt
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

_DB_PATH: str = ""


def init_db(db_path: str) -> None:
    """Create tables and seed the default admin account if the DB is new."""
    global _DB_PATH
    _DB_PATH = db_path
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    with get_conn() as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user'
                          CHECK(role IN ('admin','user')),
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL,
            last_login    TEXT
        );

        CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            filename      TEXT    NOT NULL,           -- UUID-based safe name on disk
            original_name TEXT    NOT NULL,           -- original upload name (display)
            mime_type     TEXT    NOT NULL DEFAULT 'application/octet-stream',
            size_bytes    INTEGER NOT NULL DEFAULT 0,
            uploaded_by   INTEGER NOT NULL REFERENCES users(id),
            uploaded_at   TEXT    NOT NULL,
            is_active     INTEGER NOT NULL DEFAULT 1,
            description   TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS login_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            ip_address TEXT,
            success    INTEGER NOT NULL,
            timestamp  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rate_limit (
            ip_address  TEXT    PRIMARY KEY,
            attempts    INTEGER NOT NULL DEFAULT 0,
            window_start TEXT   NOT NULL
        );
        """)

        # Seed admin user only if table is empty
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        if row[0] == 0:
            from werkzeug.security import generate_password_hash
            now = _now()
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, 'admin', ?)",
                ("admin", generate_password_hash("Admin@1234!"), now)
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, 'user', ?)",
                ("viewer", generate_password_hash("Viewer@5678!"), now)
            )
            conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── User queries ──────────────────────────────────────────────────────────────

def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
        ).fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)
        ).fetchone()


def update_last_login(user_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (_now(), user_id))


def create_user(username: str, password_hash: str, role: str = "user") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            (username, password_hash, role, _now())
        )
        assert cur.lastrowid is not None
        return cur.lastrowid


def list_users():
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, username, role, is_active, created_at, last_login "
            "FROM users ORDER BY id"
        ).fetchall()


def toggle_user_active(user_id: int, active: bool) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (int(active), user_id))


def change_password(user_id: int, new_hash: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))


# ── File queries ──────────────────────────────────────────────────────────────

def register_file(filename: str, original_name: str, mime_type: str,
                  size_bytes: int, uploaded_by: int, description: str = "") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO files (filename, original_name, mime_type, size_bytes, "
            "uploaded_by, uploaded_at, description) VALUES (?,?,?,?,?,?,?)",
            (filename, original_name, mime_type, size_bytes, uploaded_by, _now(), description)
        )
        assert cur.lastrowid is not None
        return cur.lastrowid


def get_file_by_id(file_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT f.*, u.username as uploader "
            "FROM files f JOIN users u ON f.uploaded_by=u.id "
            "WHERE f.id=? AND f.is_active=1", (file_id,)
        ).fetchone()


def list_files():
    with get_conn() as conn:
        return conn.execute(
            "SELECT f.*, u.username as uploader "
            "FROM files f JOIN users u ON f.uploaded_by=u.id "
            "WHERE f.is_active=1 ORDER BY f.uploaded_at DESC"
        ).fetchall()


def delete_file_record(file_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE files SET is_active=0 WHERE id=?", (file_id,))


# ── Audit / rate-limit queries ─────────────────────────────────────────────────

def log_login(username: Optional[str], ip: str, success: bool) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO login_log (username, ip_address, success, timestamp) VALUES (?,?,?,?)",
            (username, ip, int(success), _now())
        )


def check_rate_limit(ip: str, max_attempts: int, window_seconds: int) -> bool:
    """Return True if the IP is currently rate-limited."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT attempts, window_start FROM rate_limit WHERE ip_address=?", (ip,)
        ).fetchone()

        if row is None:
            return False

        window_start = datetime.fromisoformat(row["window_start"])
        if (now - window_start).total_seconds() > window_seconds:
            conn.execute("DELETE FROM rate_limit WHERE ip_address=?", (ip,))
            return False

        return row["attempts"] >= max_attempts


def record_failed_login(ip: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM rate_limit WHERE ip_address=?", (ip,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE rate_limit SET attempts=attempts+1 WHERE ip_address=?", (ip,)
            )
        else:
            conn.execute(
                "INSERT INTO rate_limit (ip_address, attempts, window_start) VALUES (?,1,?)",
                (ip, now)
            )


def clear_rate_limit(ip: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM rate_limit WHERE ip_address=?", (ip,))


def recent_login_log(limit: int = 50):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM login_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
