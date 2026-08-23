"""
Unit and integration tests for TRINETRA Authentication and Authorization (RBAC).
"""
import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from policy_enforcer import database, auth
from policy_enforcer.main import app


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    fd, path = tempfile.mkstemp(suffix="_test_trinetra.db")
    os.close(fd)
    db_path = Path(path)
    database.init_db(custom_path=db_path)
    yield db_path
    if db_path.exists():
        os.remove(db_path)


def test_missing_admin_password_env_fails(temp_db, monkeypatch):
    """Test that missing TRINETRA_ADMIN_PASSWORD on empty DB raises RuntimeError."""
    monkeypatch.delenv("TRINETRA_ADMIN_PASSWORD", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        auth.seed_initial_admin_if_needed(custom_db_path=temp_db)
    assert "TRINETRA_ADMIN_PASSWORD environment variable is required" in str(exc_info.value)


def test_seeds_admin_with_bcrypt(temp_db, monkeypatch):
    """Test that when TRINETRA_ADMIN_PASSWORD is set, admin is hashed with bcrypt and seeded."""
    monkeypatch.setenv("TRINETRA_ADMIN_PASSWORD", "TestAdminSecretPass123!")
    auth.seed_initial_admin_if_needed(custom_db_path=temp_db)

    user = database.get_user_by_username("admin", custom_path=temp_db)
    assert user is not None
    assert user["username"] == "admin"
    assert user["role"] == "admin"
    assert user["password_hash"] != "TestAdminSecretPass123!"
    assert auth.verify_password("TestAdminSecretPass123!", user["password_hash"])
    assert not auth.verify_password("WrongPassword!", user["password_hash"])


def test_login_flow(temp_db, monkeypatch):
    """Test login endpoint with valid, invalid, and nonexistent credentials."""
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    monkeypatch.setenv("TRINETRA_ADMIN_PASSWORD", "ValidSecretPassword#1")
    auth.seed_initial_admin_if_needed(custom_db_path=temp_db)

    # Insert an operator user
    op_hash = auth.hash_password("OperatorPass#1")
    database.insert_user(
        username="operator1",
        password_hash=op_hash,
        full_name="SOC Operator 1",
        role="operator",
        created_at="2026-08-23T00:00:00",
        custom_path=temp_db,
    )

    client = TestClient(app)

    # 1. Invalid username
    res_unknown = client.post("/auth/login", json={"username": "nobody", "password": "any"})
    assert res_unknown.status_code == 401

    # 2. Invalid password
    res_wrong_pass = client.post("/auth/login", json={"username": "admin", "password": "WrongPassword"})
    assert res_wrong_pass.status_code == 401

    # 3. Successful admin login
    res_admin = client.post("/auth/login", json={"username": "admin", "password": "ValidSecretPassword#1"})
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert "access_token" in admin_data
    assert admin_data["user"]["role"] == "admin"

    # 4. Successful operator login
    res_op = client.post("/auth/login", json={"username": "operator1", "password": "OperatorPass#1"})
    assert res_op.status_code == 200
    op_data = res_op.json()
    assert "access_token" in op_data
    assert op_data["user"]["role"] == "operator"


def test_protected_routes_and_rbac(temp_db, monkeypatch):
    """Test RBAC enforcement between admin and operator accounts."""
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    monkeypatch.setenv("TRINETRA_ADMIN_PASSWORD", "AdminPass123!")
    auth.seed_initial_admin_if_needed(custom_db_path=temp_db)

    op_hash = auth.hash_password("OperatorPass123!")
    database.insert_user(
        username="operator1",
        password_hash=op_hash,
        full_name="SOC Operator 1",
        role="operator",
        created_at="2026-08-23T00:00:00",
        custom_path=temp_db,
    )

    client = TestClient(app)

    # Unauthenticated request to protected endpoint
    res_unauth = client.get("/dashboard/state")
    assert res_unauth.status_code == 401

    # Login as operator
    op_token = client.post("/auth/login", json={"username": "operator1", "password": "OperatorPass123!"}).json()["access_token"]
    op_headers = {"Authorization": f"Bearer {op_token}"}

    # Operator accessing operator/admin allowed endpoint
    res_op_dash = client.get("/dashboard/state", headers=op_headers)
    assert res_op_dash.status_code == 200

    # Operator attempting admin-only endpoint (POST /policy/config/thresholds)
    res_op_admin_ep = client.post("/policy/config/thresholds", json={"safe_max": 25}, headers=op_headers)
    assert res_op_admin_ep.status_code == 403

    # Operator attempting admin-only database clear
    res_op_clear = client.post("/dashboard/clear", headers=op_headers)
    assert res_op_clear.status_code == 403

    # Login as admin
    admin_token = client.post("/auth/login", json={"username": "admin", "password": "AdminPass123!"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin accessing admin-only endpoint
    res_admin_thresh = client.post("/policy/config/thresholds", json={"safe_max": 25}, headers=admin_headers)
    assert res_admin_thresh.status_code == 200

    # Admin clearing dashboard
    res_admin_clear = client.post("/dashboard/clear", headers=admin_headers)
    assert res_admin_clear.status_code == 200
    assert res_admin_clear.json()["cleared"] is True


def test_token_expiration_and_tampering(temp_db, monkeypatch):
    """Test expired and malformed tokens are rejected."""
    monkeypatch.setattr(database, "DB_PATH", temp_db)
    from datetime import timedelta
    expired_token = auth.create_access_token(username="admin", role="admin", expires_delta=timedelta(seconds=-10))

    client = TestClient(app)

    # Expired token
    res_exp = client.get("/dashboard/state", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_exp.status_code == 401
    assert "expired" in res_exp.json()["detail"].lower()

    # Malformed token
    res_mal = client.get("/dashboard/state", headers={"Authorization": "Bearer not.a.valid.jwt.token"})
    assert res_mal.status_code == 401
