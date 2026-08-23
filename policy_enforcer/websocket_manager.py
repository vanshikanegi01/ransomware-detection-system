"""
Manages active WebSocket connections with strict application-level authentication.
Broadcasts telemetry events ONLY to authenticated clients.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("trinetra.websocket")


class ConnectionManager:
    def __init__(self):
        # Maps WebSocket connection to its authenticated user data dict
        self._authenticated_clients: Dict[WebSocket, Dict[str, Any]] = {}
        # Set of connections that have connected but not yet authenticated
        self._pending_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register_pending(self, websocket: WebSocket) -> None:
        """Register a newly accepted connection into pending unauthenticated pool."""
        async with self._lock:
            self._pending_connections.add(websocket)

    async def mark_authenticated(self, websocket: WebSocket, user_data: Dict[str, Any]) -> None:
        """Promote a connection from pending to authenticated pool."""
        async with self._lock:
            if websocket in self._pending_connections:
                self._pending_connections.remove(websocket)
            self._authenticated_clients[websocket] = user_data
        logger.info("WebSocket connection authenticated for user: %s", user_data.get("sub", "unknown"))

    def is_authenticated(self, websocket: WebSocket) -> bool:
        return websocket in self._authenticated_clients

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove connection from all pools upon disconnect."""
        async with self._lock:
            if websocket in self._pending_connections:
                self._pending_connections.remove(websocket)
            if websocket in self._authenticated_clients:
                del self._authenticated_clients[websocket]

    async def broadcast(self, message: dict) -> None:
        """
        Broadcasts telemetry event ONLY to authenticated connections.
        Stale/broken connections are cleaned up safely.
        """
        payload = json.dumps(message)
        stale = []

        async with self._lock:
            recipients = list(self._authenticated_clients.keys())

        for connection in recipients:
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.debug("Failed sending WebSocket message to client: %s", e)
                stale.append(connection)

        if stale:
            async with self._lock:
                for c in stale:
                    if c in self._authenticated_clients:
                        del self._authenticated_clients[c]
                    if c in self._pending_connections:
                        self._pending_connections.remove(c)
