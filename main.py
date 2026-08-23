"""
TRINETRA Backend - FastAPI application

Wires together:
    Watchdog/ML signal -> Policy Engine -> Enforcer -> Vaultkeeper
    -> SQLite event log -> WebSocket broadcast -> Dashboard

Run with:
    uvicorn backend.main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from policy_engine.policy_engine import PolicyEngine
from policy_engine.models import BehavioralSignal, ThresholdUpdate, EnforcerConfigUpdate
from enforcer.enforcer import Enforcer
from vaultkeeper.vaultkeeper import Vaultkeeper
from simulator.simulator import RansomwareSimulator

from . import database
from .websocket_manager import ConnectionManager

app = FastAPI(title="TRINETRA Policy Engine + Enforcer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = ConnectionManager()
enforcer = Enforcer()
vaultkeeper = Vaultkeeper()


def event_sink(event: dict) -> None:
    """Called synchronously by the Policy Engine/Enforcer/Vaultkeeper for
    every event. Persists to SQLite and schedules a WebSocket broadcast
    on the running event loop."""
    database.insert_event(event)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(manager.broadcast(event))
    except RuntimeError:
        pass


policy_engine = PolicyEngine(event_sink=event_sink, enforcer=enforcer, vaultkeeper=vaultkeeper)
simulator = RansomwareSimulator(policy_engine, vaultkeeper, event_sink=event_sink)


@app.on_event("startup")
async def startup():
    database.init_db()


# ---------------------------------------------------------------------
# Policy Engine API
# ---------------------------------------------------------------------
@app.post("/policy/evaluate")
async def evaluate_policy(signal: BehavioralSignal):
    return policy_engine.evaluate(signal)


@app.get("/policy/config")
async def get_policy_config():
    return policy_engine.get_config()


@app.post("/policy/config/thresholds")
async def update_thresholds(update: ThresholdUpdate):
    return policy_engine.update_thresholds(update.dict())


@app.post("/policy/config/enforcer")
async def update_enforcer_config(update: EnforcerConfigUpdate):
    return policy_engine.update_enforcer_config(update.dict())


# ---------------------------------------------------------------------
# Enforcer API
# ---------------------------------------------------------------------
@app.post("/enforcer/unlock-all")
async def unlock_all_files():
    result = enforcer.unlock_all_files()
    event_sink({"event": "FILES_UNLOCKED", "details": result})
    return result


@app.get("/enforcer/log")
async def enforcer_log(limit: int = 100):
    return enforcer.recent_log(limit)


# ---------------------------------------------------------------------
# Vaultkeeper API
# ---------------------------------------------------------------------
@app.post("/vaultkeeper/snapshot")
async def snapshot_backup(paths: list[str] | None = None):
    return vaultkeeper.snapshot(paths)


# ---------------------------------------------------------------------
# Simulator API
# ---------------------------------------------------------------------
@app.post("/simulate/start")
async def start_simulation():
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, simulator.run)
    return result


# ---------------------------------------------------------------------
# Dashboard state + event history
# ---------------------------------------------------------------------
@app.get("/dashboard/events")
async def dashboard_events(limit: int = 200):
    return database.get_recent_events(limit)


@app.get("/dashboard/state")
async def dashboard_state():
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


@app.post("/dashboard/clear")
async def clear_dashboard():
    database.clear_events()
    return {"cleared": True}


# ---------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "TRINETRA Policy Engine + Enforcer"}
