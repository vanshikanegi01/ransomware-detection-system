"""
Unit and Integration Tests for Heartbeat Monitoring (Member 1 - TRINETRA).

Verifies HeartbeatData model serialization, HeartbeatMonitor periodic background
emission, start/stop lifecycle, error containment, and WatchdogAgent integration.
"""

import json
import os
import time
from pathlib import Path
from typing import List

import pytest

from watcher import (
    EventData,
    EventType,
    HeartbeatData,
    HeartbeatMonitor,
    ProcessTelemetry,
    WatchdogAgent,
)


class TestHeartbeatModels:
    """Tests for HeartbeatData dataclass and serialization."""

    def test_heartbeat_data_defaults(self):
        hb = HeartbeatData()
        assert hb.event_type == "heartbeat"
        assert hb.status == "active"
        assert hb.pid == os.getpid()
        assert hb.uptime_seconds == 0.0
        assert hb.events_processed == 0
        assert isinstance(hb.heartbeat_id, str)
        assert isinstance(hb.timestamp, str)

    def test_heartbeat_data_serialization(self):
        proc = ProcessTelemetry(pid=1234, name="agent.exe", cpu_percent=2.5, memory_percent=1.2)
        hb = HeartbeatData(
            status="healthy",
            pid=1234,
            uptime_seconds=42.5,
            events_processed=15,
            watch_dir="C:\\test_sandbox",
            process_telemetry=proc,
            metadata={"version": "1.0"},
        )

        d = hb.to_dict()
        assert d["event_type"] == "heartbeat"
        assert d["status"] == "healthy"
        assert d["pid"] == 1234
        assert d["uptime_seconds"] == 42.5
        assert d["events_processed"] == 15
        assert d["watch_dir"] == "C:\\test_sandbox"
        assert d["process_telemetry"]["name"] == "agent.exe"
        assert d["metadata"]["version"] == "1.0"

        json_str = hb.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["status"] == "healthy"

        restored = HeartbeatData.from_dict(d)
        assert restored.heartbeat_id == hb.heartbeat_id
        assert restored.status == "healthy"
        assert restored.pid == 1234
        assert restored.uptime_seconds == 42.5
        assert restored.events_processed == 15
        assert restored.process_telemetry is not None
        assert restored.process_telemetry.name == "agent.exe"

    def test_event_type_heartbeat_enum(self):
        assert EventType.from_str("heartbeat") == EventType.HEARTBEAT
        assert EventType.HEARTBEAT.value == "heartbeat"


class TestHeartbeatMonitor:
    """Tests for HeartbeatMonitor background daemon thread and emitter."""

    def test_heartbeat_monitor_lifecycle(self, tmp_path: Path):
        monitor = HeartbeatMonitor(interval=5.0, watch_dir=tmp_path)
        assert not monitor.is_alive()
        monitor.start()
        assert monitor.is_alive()
        monitor.stop()
        assert not monitor.is_alive()

    def test_heartbeat_monitor_context_manager(self, tmp_path: Path):
        with HeartbeatMonitor(interval=5.0, watch_dir=tmp_path) as monitor:
            assert monitor.is_alive()
        assert not monitor.is_alive()

    def test_heartbeat_manual_emit(self, tmp_path: Path):
        received: List[HeartbeatData] = []

        def callback(hb: HeartbeatData):
            received.append(hb)

        status_provider = lambda: {"uptime_seconds": 12.0, "events_processed": 3, "status": "active"}

        monitor = HeartbeatMonitor(
            interval=10.0,
            callback=callback,
            get_status_fn=status_provider,
            watch_dir=tmp_path,
        )

        hb = monitor.emit_heartbeat()
        assert len(received) == 1
        assert received[0].uptime_seconds == 12.0
        assert received[0].events_processed == 3
        assert received[0].status == "active"
        assert received[0].pid == os.getpid()
        assert hb.heartbeat_id == received[0].heartbeat_id

    def test_heartbeat_periodic_emission(self, tmp_path: Path):
        received: List[HeartbeatData] = []

        def callback(hb: HeartbeatData):
            received.append(hb)

        monitor = HeartbeatMonitor(interval=0.1, callback=callback, watch_dir=tmp_path)
        monitor.start()
        try:
            time.sleep(0.35)
        finally:
            monitor.stop()

        assert len(received) >= 2
        for hb in received:
            assert hb.event_type == "heartbeat"
            assert hb.pid == os.getpid()

    def test_heartbeat_invalid_interval(self):
        with pytest.raises(ValueError):
            HeartbeatMonitor(interval=0)
        with pytest.raises(ValueError):
            HeartbeatMonitor(interval=-1.0)

    def test_heartbeat_callback_error_handling(self, tmp_path: Path):
        def failing_callback(hb: HeartbeatData):
            raise RuntimeError("Callback crash simulation")

        monitor = HeartbeatMonitor(interval=10.0, callback=failing_callback, watch_dir=tmp_path)
        # emit_heartbeat should catch the exception and not propagate
        hb = monitor.emit_heartbeat()
        assert hb is not None


class TestWatchdogAgentHeartbeatIntegration:
    """Tests for WatchdogAgent coordinator with HeartbeatMonitor."""

    def test_agent_heartbeat_coordination(self, tmp_path: Path):
        received_heartbeats: List[HeartbeatData] = []

        def hb_callback(hb: HeartbeatData):
            received_heartbeats.append(hb)

        agent = WatchdogAgent(
            watch_dir=tmp_path,
            recursive=True,
            enable_heartbeat=True,
            heartbeat_interval=0.1,
            heartbeat_callbacks=[hb_callback],
        )

        with agent:
            assert agent.is_alive()
            assert agent.heartbeat_monitor is not None
            assert agent.heartbeat_monitor.is_alive()
            time.sleep(0.35)

        assert not agent.is_alive()
        assert not agent.heartbeat_monitor.is_alive()
        assert len(received_heartbeats) >= 2
        for hb in received_heartbeats:
            assert hb.status == "active"
            assert hb.uptime_seconds >= 0.0

    def test_agent_heartbeat_callbacks_add_remove(self, tmp_path: Path):
        agent = WatchdogAgent(watch_dir=tmp_path)
        cb = lambda hb: None
        agent.add_heartbeat_callback(cb)
        assert cb in agent._heartbeat_callbacks
        agent.remove_heartbeat_callback(cb)
        assert cb not in agent._heartbeat_callbacks

    def test_agent_emit_heartbeat_on_demand(self, tmp_path: Path):
        agent = WatchdogAgent(watch_dir=tmp_path, enable_heartbeat=True)
        hb = agent.emit_heartbeat()
        assert hb is not None
        assert hb.event_type == "heartbeat"
        assert hb.pid == os.getpid()

    def test_agent_heartbeat_with_canary_and_file_events(self, tmp_path: Path):
        file_events: List[EventData] = []
        heartbeats: List[HeartbeatData] = []

        agent = WatchdogAgent(
            watch_dir=tmp_path,
            enable_canary=True,
            enable_heartbeat=True,
            heartbeat_interval=0.1,
            callbacks=[lambda ev: file_events.append(ev)],
            heartbeat_callbacks=[lambda hb: heartbeats.append(hb)],
        )

        with agent:
            assert agent.is_alive()
            time.sleep(0.2)

            # Deploy canary tripwire file
            deployed = agent.deploy_canaries(filenames=["!_canary_tripwire.docx"])
            assert len(deployed) == 1
            time.sleep(0.3)

            # Create a regular non-canary file
            (tmp_path / "notes.txt").write_text("regular data", encoding="utf-8")
            time.sleep(0.3)

        assert len(heartbeats) >= 1
        assert len(file_events) >= 1
        canary_events = [e for e in file_events if e.is_canary]
        assert len(canary_events) >= 1
        assert canary_events[0].severity == "high"
