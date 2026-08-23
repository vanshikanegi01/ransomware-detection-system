"""
Unit and integration tests for WebSocket application-level authentication handshake.
"""
import os
import json
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from policy_enforcer import database, auth
from policy_enforcer.main import app, manager


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    fd, path = tempfile.mkstemp(suffix="_test_ws_trinetra.db")
    os.close(fd)
    db_path = Path(path)
    database.init_db(custom_path=db_path)
    yield db_path
    if db_path.exists():
        os.remove(db_path)


def test_websocket_invalid_token(temp_db, monkeypatch):
    """Test that connecting with invalid handshake message or invalid token closes socket."""
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    client = TestClient(app)

    # 1. Invalid message format
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text(json.dumps({"type": "invalid"}))
        res = websocket.receive_json()
        assert res["type"] == "auth_error"

    # 2. Invalid token
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text(json.dumps({"type": "auth", "token": "bad_token"}))
        res = websocket.receive_json()
        assert res["type"] == "auth_error"


def test_websocket_valid_auth_and_broadcast(temp_db, monkeypatch):
    """Test that valid JWT handshake succeeds and authenticated client receives broadcast events."""
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    monkeypatch.setenv("TRINETRA_ADMIN_PASSWORD", "ValidSecretPassword#1")
    auth.seed_initial_admin_if_needed(custom_db_path=temp_db)

    client = TestClient(app)
    login_res = client.post("/auth/login", json={"username": "admin", "password": "ValidSecretPassword#1"})
    token = login_res.json()["access_token"]

    with client.websocket_connect("/ws") as websocket:
        # Send auth handshake
        websocket.send_text(json.dumps({"type": "auth", "token": token}))
        res = websocket.receive_json()
        assert res["type"] == "auth_success"

        # Broadcast an event
        import asyncio
        test_event = {"event": "THREAT_CONFIRMED", "process": "malware.exe", "risk_score": 95}
        asyncio.run(manager.broadcast(test_event))

        event_received = websocket.receive_json()
        assert event_received["event"] == "THREAT_CONFIRMED"
        assert event_received["process"] == "malware.exe"
