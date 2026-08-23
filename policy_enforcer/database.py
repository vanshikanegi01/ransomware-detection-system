"""
SQLite persistence for TRINETRA real-time events and user authentication,
per the FastAPI/WebSocket/SQLite architecture.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "db" / "trinetra.db"


def get_connection(custom_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = custom_path or DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(custom_path: Optional[Path] = None) -> None:
    conn = get_connection(custom_path)
    # 1. Existing events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    """)
    # 2. Users table for authentication
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------------
# Event Log Operations (Preserved Intact)
# -----------------------------------------------------------------------------
def insert_event(event: dict, custom_path: Optional[Path] = None) -> int:
    conn = get_connection(custom_path)
    cur = conn.execute(
        "INSERT INTO events (timestamp, event, payload) VALUES (?, ?, ?)",
        (event.get("timestamp", ""), event.get("event", "UNKNOWN"), json.dumps(event)),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_recent_events(limit: int = 200, custom_path: Optional[Path] = None) -> List[dict]:
    conn = get_connection(custom_path)
    rows = conn.execute(
        "SELECT payload FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    events = [json.loads(r["payload"]) for r in rows]
    events.reverse()
    return events


def clear_events(custom_path: Optional[Path] = None) -> None:
    conn = get_connection(custom_path)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------------
# User Storage & Authentication Queries
# -----------------------------------------------------------------------------
def get_user_count(custom_path: Optional[Path] = None) -> int:
    conn = get_connection(custom_path)
    row = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
    conn.close()
    return row["count"] if row else 0


def get_user_by_username(username: str, custom_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection(custom_path)
    row = conn.execute(
        "SELECT id, username, password_hash, full_name, role, created_at, last_login FROM users WHERE username = ?",
        (username.strip(),),
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def insert_user(
    username: str,
    password_hash: str,
    full_name: str,
    role: str = "operator",
    created_at: str = "",
    custom_path: Optional[Path] = None,
) -> int:
    conn = get_connection(custom_path)
    cur = conn.execute(
        """
        INSERT INTO users (username, password_hash, full_name, role, created_at, last_login)
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (username.strip(), password_hash, full_name.strip(), role.strip(), created_at),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def update_last_login(username: str, timestamp: str, custom_path: Optional[Path] = None) -> None:
    conn = get_connection(custom_path)
    conn.execute(
        "UPDATE users SET last_login = ? WHERE username = ?",
        (timestamp, username.strip()),
    )
    conn.commit()
    conn.close()


def get_all_users(custom_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_connection(custom_path)
    rows = conn.execute(
        "SELECT id, username, full_name, role, created_at, last_login FROM users ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
