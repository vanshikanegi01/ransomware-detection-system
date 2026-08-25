"""
TRINETRA Backend - FastAPI application

Wires together:
    Watchdog/ML signal -> Policy Engine -> Enforcer -> Vaultkeeper
    -> SQLite event log -> Authenticated WebSocket broadcast -> SOC Dashboard

Run with:
    uvicorn policy_enforcer.main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .policy_engine import PolicyEngine
from .models import BehavioralSignal, ThresholdUpdate, EnforcerConfigUpdate
from .enforcer import Enforcer
from .vaultkeeper import Vaultkeeper
from .simulator import RansomwareSimulator

from . import database
from . import auth
from .auth_models import LoginRequest, TokenResponse, UserResponse
from .websocket_manager import ConnectionManager

logger = logging.getLogger("trinetra.main")

app = FastAPI(
    title="TRINETRA Policy Engine + Enforcer API",
    description="Cybersecurity SOC Backend for passive ransomware detection, policy enforcement, and vaultkeeper recovery.",
    version="1.0.0",
)

# CORS configuration restricted to desktop and local development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "tauri://localhost",
        "https://tauri.localhost",
        "http://tauri.localhost",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = ConnectionManager()
enforcer = Enforcer()
vaultkeeper = Vaultkeeper()


def event_sink(event: dict) -> None:
    """
    Called synchronously by Policy Engine / Enforcer / Vaultkeeper for every event.
    Persists to SQLite and schedules an authenticated WebSocket broadcast.
    """
    database.insert_event(event)
    try:
        if _main_loop and _main_loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(event), _main_loop)
    except Exception as e:
        logger.error(f'Broadcast failed: {e}')


policy_engine = PolicyEngine(event_sink=event_sink, enforcer=enforcer, vaultkeeper=vaultkeeper)
simulator = RansomwareSimulator(policy_engine, vaultkeeper, event_sink=event_sink)


_main_loop = None

@app.on_event("startup")
async def startup():
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    # 1. Initialize database tables idempotently
    database.init_db()
    # 2. Seed initial administrator if users table is empty (fails fast if TRINETRA_ADMIN_PASSWORD is unset)
    auth.seed_initial_admin_if_needed()


# ---------------------------------------------------------------------
# Public Health Check
# ---------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": "TRINETRA Policy Engine + Enforcer"}


# ---------------------------------------------------------------------
# Authentication API (Public / User Verification)
# ---------------------------------------------------------------------
@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(req: LoginRequest):
    user = database.get_user_by_username(req.username)
    if not user or not auth.verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last login timestamp
    auth.database.update_last_login(user["username"], auth._utc_now_iso())

    access_token = auth.create_access_token(username=user["username"], role=user["role"])
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            username=user["username"],
            full_name=user["full_name"],
            role=user["role"],
            created_at=user.get("created_at"),
            last_login=user.get("last_login"),
        ),
    )


@app.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_profile(current_user: Dict[str, Any] = Depends(auth.get_current_user)):
    return UserResponse(
        username=current_user["username"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        created_at=current_user.get("created_at"),
        last_login=current_user.get("last_login"),
    )


# ---------------------------------------------------------------------
# Policy Engine API (Authenticated)
# ---------------------------------------------------------------------
@app.post("/policy/evaluate", tags=["Policy Engine"])
async def evaluate_policy(
    signal: BehavioralSignal,
    current_user: Dict[str, Any] = Depends(auth.get_current_user),
):
    return policy_engine.evaluate(signal)


@app.get("/policy/config", tags=["Policy Engine"])
async def get_policy_config(current_user: Dict[str, Any] = Depends(auth.get_current_user)):
    return policy_engine.get_config()


@app.post("/policy/config/thresholds", tags=["Policy Engine Admin"])
async def update_thresholds(
    update: ThresholdUpdate,
    admin_user: Dict[str, Any] = Depends(auth.require_admin),
):
    return policy_engine.update_thresholds(update.dict())


@app.post("/policy/config/enforcer", tags=["Policy Engine Admin"])
async def update_enforcer_config(
    update: EnforcerConfigUpdate,
    admin_user: Dict[str, Any] = Depends(auth.require_admin),
):
    return policy_engine.update_enforcer_config(update.dict())


# ---------------------------------------------------------------------
# Enforcer API (Authenticated)
# ---------------------------------------------------------------------
@app.post("/enforcer/unlock-all", tags=["Enforcer"])
async def unlock_all_files(current_user: Dict[str, Any] = Depends(auth.get_current_user)):
    result = enforcer.unlock_all_files()
    event_sink({"event": "FILES_UNLOCKED", "details": result})
    return result


@app.get("/enforcer/log", tags=["Enforcer"])
async def enforcer_log(
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(auth.get_current_user),
):
    return enforcer.recent_log(limit)


# ---------------------------------------------------------------------
# Vaultkeeper API (Authenticated)
# ---------------------------------------------------------------------
@app.post("/vaultkeeper/snapshot", tags=["Vaultkeeper"])
async def snapshot_backup(
    paths: list[str] | None = None,
    current_user: Dict[str, Any] = Depends(auth.get_current_user),
):
    return vaultkeeper.snapshot(paths)


# ---------------------------------------------------------------------
# Simulator API (Authenticated)
# ---------------------------------------------------------------------
@app.post("/simulate/start", tags=["Simulator"])
async def start_simulation(current_user: Dict[str, Any] = Depends(auth.get_current_user)):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, simulator.run)
    return result


# ---------------------------------------------------------------------
# Dashboard State + Event History (Authenticated)
# ---------------------------------------------------------------------
@app.get("/dashboard/events", tags=["Dashboard"])
async def dashboard_events(
    limit: int = 200,
    current_user: Dict[str, Any] = Depends(auth.get_current_user),
):
    return database.get_recent_events(limit)


@app.get("/dashboard/state", tags=["Dashboard"])
async def dashboard_state(current_user: Dict[str, Any] = Depends(auth.get_current_user)):
    events = database.get_recent_events(50)
    latest_decision = next(
        (e for e in reversed(events)
         if e.get("event") in ("SAFE", "SUSPICIOUS", "HIGH_RISK", "THREAT_CONFIRMED")),
        None,
    )
    return {
        "latest_decision": latest_decision,
        "recent_events": events,
        "enforcer_config": policy_engine.get_config()["enforcer"],
        "thresholds": policy_engine.get_config()["thresholds"],
    }


@app.post("/dashboard/clear", tags=["Dashboard Admin"])
async def clear_dashboard(admin_user: Dict[str, Any] = Depends(auth.require_admin)):
    database.clear_events()
    return {"cleared": True}


# ---------------------------------------------------------------------
# Authenticated WebSocket Endpoint with Handshake Protocol
# ---------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await manager.register_pending(websocket)

    # 1. Wait for Application-level Auth Handshake with 5.0 second timeout
    try:
        raw_msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        try:
            data = json.loads(raw_msg)
        except Exception:
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Malformed JSON handshake."}))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            await manager.disconnect(websocket)
            return

        if data.get("type") != "auth" or not data.get("token"):
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Expected auth handshake message."}))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            await manager.disconnect(websocket)
            return

        token = data["token"]
        try:
            payload = auth.decode_access_token(token)
            username = payload.get("sub")
            user = database.get_user_by_username(username) if username else None
            if not user:
                raise ValueError("User not found.")
        except Exception:
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Invalid or expired token."}))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            await manager.disconnect(websocket)
            return

        # Successfully Authenticated
        await manager.mark_authenticated(websocket, user)
        await websocket.send_text(json.dumps({"type": "auth_success", "message": "Authenticated successfully."}))

    except asyncio.TimeoutError:
        try:
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Authentication timeout."}))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass
        await manager.disconnect(websocket)
        return
    except Exception as e:
        logger.error("Error during WebSocket handshake: %s", e)
        await manager.disconnect(websocket)
        return

    # 2. Main loop: Keep connection alive, listen for incoming ping/messages
    try:
        while True:
            # Client can send keepalive pings or command messages
            msg = await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)
