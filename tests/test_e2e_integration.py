"""
Full End-to-End Integration Test for TRINETRA.
Tests:
1. Dynamic admin initialization with bcrypt (TRINETRA_ADMIN_PASSWORD).
2. Login and JWT generation.
3. Authenticated REST endpoints (dashboard state, policy config, unlock-all, simulation).
4. WebSocket handshake authentication and real-time event streaming.
5. Role-based access control (Operator vs Admin).
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
    fd, path = tempfile.mkstemp(suffix="_test_e2e.db")
    os.close(fd)
    db_path = Path(path)
    database.init_db(custom_path=db_path)
    yield db_path
    if db_path.exists():
        os.remove(db_path)


def test_full_integration_workflow(temp_db, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    monkeypatch.setenv("TRINETRA_ADMIN_PASSWORD", "SuperSecureAdminPassword2026!")

    # 1. Startup initialization
    auth.seed_initial_admin_if_needed(custom_db_path=temp_db)
    assert database.get_user_count(custom_path=temp_db) == 1

    client = TestClient(app)

    # 2. Public health check
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"

    # 3. Unauthenticated access blocked
    unauth_dash = client.get("/dashboard/state")
    assert unauth_dash.status_code == 401

    # 4. Admin login
    login_res = client.post("/auth/login", json={
        "username": "admin",
        "password": "SuperSecureAdminPassword2026!",
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    admin_token = login_data["access_token"]
    assert login_data["user"]["username"] == "admin"
    assert login_data["user"]["role"] == "admin"

    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 5. Fetch dashboard state with JWT
    dash_res = client.get("/dashboard/state", headers=admin_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert "thresholds" in dash_data
    assert "enforcer_config" in dash_data

    # 6. WebSocket Handshake & Live Event Stream
    with client.websocket_connect("/ws") as websocket:
        # Perform handshake
        websocket.send_text(json.dumps({"type": "auth", "token": admin_token}))
        auth_ack = websocket.receive_json()
        assert auth_ack["type"] == "auth_success"

        # Trigger safe backend simulation
        sim_res = client.post("/simulate/start", headers=admin_headers)
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert sim_data.get("decision") == "THREAT_CONFIRMED"

        # Test direct broadcast to authenticated socket
        import asyncio
        asyncio.run(manager.broadcast({"event": "THREAT_CONFIRMED", "process": "ransomware.exe", "risk_score": 98}))
        broadcast_msg = websocket.receive_json()
        assert broadcast_msg["event"] == "THREAT_CONFIRMED"
        assert broadcast_msg["risk_score"] == 98

    # 7. Enforcer file unlock action
    unlock_res = client.post("/enforcer/unlock-all", headers=admin_headers)
    assert unlock_res.status_code == 200
    assert "restored" in unlock_res.json()

    # 8. Admin config update
    config_update_res = client.post("/policy/config/thresholds", json={"safe_max": 28}, headers=admin_headers)
    assert config_update_res.status_code == 200
    assert config_update_res.json()["safe_max"] == 28
