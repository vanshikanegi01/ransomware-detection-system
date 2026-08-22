"""
Unit and Integration Tests for Windows Background Service (Member 1 - TRINETRA).

Verifies ServiceConfig serialization, ServiceState transitions, WatchdogService
lifecycle (start/stop/supervisor), status callbacks, and file/heartbeat coordination
safely in non-admin user mode without modifying real Windows Service Manager state.
"""

import json
import os
import time
from pathlib import Path
from typing import List

import pytest

from watcher import (
    EventData,
    HeartbeatData,
    ServiceConfig,
    ServiceState,
    WatchdogAgent,
    WatchdogService,
)


class TestServiceConfig:
    """Tests for ServiceConfig dataclass and serialization."""

    def test_default_config(self):
        cfg = ServiceConfig()
        assert cfg.service_name == "TrinetraWatchdog"
        assert "TRINETRA" in cfg.display_name
        assert cfg.enable_canary is True
        assert cfg.enable_heartbeat is True
        assert cfg.heartbeat_interval == 30.0
        assert cfg.recursive is True

    def test_custom_config_and_serialization(self, tmp_path: Path):
        cfg = ServiceConfig(
            service_name="CustomWatchdogSvc",
            display_name="Custom Display",
            watch_dir=str(tmp_path),
            heartbeat_interval=5.0,
            enable_canary=False,
        )
        d = cfg.to_dict()
        assert d["service_name"] == "CustomWatchdogSvc"
        assert d["heartbeat_interval"] == 5.0
        assert d["enable_canary"] is False

        json_str = cfg.to_json()
        assert "CustomWatchdogSvc" in json_str

        restored = ServiceConfig.from_dict(d)
        assert restored.service_name == cfg.service_name
        assert restored.watch_dir == cfg.watch_dir
        assert restored.heartbeat_interval == 5.0
        assert restored.enable_canary is False


class TestServiceLifecycle:
    """Tests for WatchdogService lifecycle and state transitions."""

    def test_service_start_stop(self, tmp_path: Path):
        config = ServiceConfig(
            watch_dir=str(tmp_path),
            heartbeat_interval=0.2,
            enable_canary=True,
            enable_heartbeat=True,
        )
        service = WatchdogService(config=config)
        assert service.state == ServiceState.STOPPED
        assert not service.is_running()

        service.start(async_mode=True)
        try:
            assert service.state == ServiceState.RUNNING
            assert service.is_running()
            assert service.agent is not None
            assert service.agent.is_alive()
        finally:
            service.stop()

        assert service.state == ServiceState.STOPPED
        assert not service.is_running()

    def test_service_context_manager(self, tmp_path: Path):
        config = ServiceConfig(watch_dir=str(tmp_path), heartbeat_interval=0.2)
        with WatchdogService(config=config) as svc:
            assert svc.is_running()
            assert svc.state == ServiceState.RUNNING
        assert not svc.is_running()
        assert svc.state == ServiceState.STOPPED

    def test_service_status_callbacks(self, tmp_path: Path):
        recorded_states: List[ServiceState] = []

        def on_status_change(state: ServiceState):
            recorded_states.append(state)

        config = ServiceConfig(watch_dir=str(tmp_path), heartbeat_interval=0.2)
        service = WatchdogService(config=config)
        service.add_status_callback(on_status_change)

        service.start(async_mode=True)
        time.sleep(0.1)
        service.stop()

        assert ServiceState.STARTING in recorded_states
        assert ServiceState.RUNNING in recorded_states
        assert ServiceState.STOPPING in recorded_states
        assert ServiceState.STOPPED in recorded_states

    def test_service_get_status_snapshot(self, tmp_path: Path):
        config = ServiceConfig(watch_dir=str(tmp_path), heartbeat_interval=0.2)
        service = WatchdogService(config=config)
        with service:
            status = service.get_service_status()
            assert status["service_name"] == "TrinetraWatchdog"
            assert status["state"] == "running"
            assert status["pid"] == os.getpid()
            assert status["uptime_seconds"] >= 0.0
            assert "watch_dir" in status


class TestServiceCoordination:
    """Tests verifying service coordinates file, canary, and heartbeat monitors."""

    def test_service_processes_events_and_heartbeats(self, tmp_path: Path):
        captured_events: List[EventData] = []
        captured_heartbeats: List[HeartbeatData] = []

        config = ServiceConfig(
            watch_dir=str(tmp_path),
            heartbeat_interval=0.1,
            enable_canary=True,
            enable_heartbeat=True,
        )

        agent = WatchdogAgent(
            watch_dir=tmp_path,
            enable_canary=True,
            enable_heartbeat=True,
            heartbeat_interval=0.1,
            callbacks=[lambda ev: captured_events.append(ev)],
            heartbeat_callbacks=[lambda hb: captured_heartbeats.append(hb)],
        )

        service = WatchdogService(config=config, agent=agent)

        with service:
            time.sleep(0.2)
            # 1. Deploy canary file
            canary_paths = agent.deploy_canaries(filenames=["!_canary_service_test.docx"])
            assert len(canary_paths) == 1
            time.sleep(0.3)

            # 2. Create normal file
            (tmp_path / "service_data.txt").write_text("service test content", encoding="utf-8")
            time.sleep(0.3)

        assert len(captured_heartbeats) >= 1
        assert len(captured_events) >= 1

        canary_alerts = [e for e in captured_events if e.is_canary]
        assert len(canary_alerts) >= 1
        assert canary_alerts[0].severity == "high"
