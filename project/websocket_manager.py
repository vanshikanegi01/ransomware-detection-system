"""
Manages active WebSocket connections and broadcasts events to all
connected dashboard clients in real time.
"""
from __future__ import annotations

import asyncio
import json
from typing import List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        payload = json.dumps(message)
        stale = []
        async with self._lock:
            connections = list(self.active_connections)
        for connection in connections:
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)
        if stale:
            async with self._lock:
                for c in stale:
                    if c in self.active_connections:
                        self.active_connections.remove(c)
