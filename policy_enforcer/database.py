"""
SQLite persistence for TRINETRA real-time events, per the existing
FastAPI/WebSocket/SQLite dashboard architecture.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "db" / "trinetra.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def insert_event(event: dict) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO events (timestamp, event, payload) VALUES (?, ?, ?)",
        (event.get("timestamp", ""), event.get("event", "UNKNOWN"), json.dumps(event)),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def get_recent_events(limit: int = 200) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT payload FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    events = [json.loads(r["payload"]) for r in rows]
    events.reverse()
    return events


def clear_events() -> None:
    conn = get_connection()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
