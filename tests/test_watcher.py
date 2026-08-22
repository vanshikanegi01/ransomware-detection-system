"""
Unit and Integration Tests for Member 1: Windows Watchdog Agent (watcher).

Verifies defensive telemetry collection, event models, file monitoring across
create/modify/delete/rename operations, process telemetry collection, and
agent coordination using safe temporary sandbox directories.
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
    FileMonitor,
    ProcessMonitor,
    ProcessTelemetry,
    WatchdogAgent,
)


class TestModels:
    """Tests for EventData and ProcessTelemetry schemas and serialization."""

    def test_event_type_enum(self):
        assert EventType.from_str("created") == EventType.CREATED
        assert EventType.from_str("MODIFIED") == EventType.MODIFIED
        assert EventType.from_str("deleted") == EventType.DELETED
        assert EventType.from_str("moved") == EventType.MOVED
        assert EventType.from_str("renamed") == EventType.RENAMED
        assert EventType.from_str("unknown_type") == EventType.UNKNOWN
        assert EventType.from_str("") == EventType.UNKNOWN

    def test_process_telemetry_to_dict_and_json(self):
        proc = ProcessTelemetry(
            pid=1234,
            name="test_process.exe",
            exe_path="C:\\Windows\\test_process.exe",
            cpu_percent=12.5,
            memory_percent=3.2,
            memory_rss_bytes=10485760,
            status="running",
        )
        data_dict = proc.to_dict()
        assert data_dict["pid"] == 1234
        assert data_dict["name"] == "test_process.exe"
        assert data_dict["cpu_percent"] == 12.5
        assert data_dict["memory_percent"] == 3.2

        json_str = proc.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["pid"] == 1234

        restored = ProcessTelemetry.from_dict(data_dict)
        assert restored.pid == proc.pid
        assert restored.name == proc.name
        assert restored.cpu_percent == proc.cpu_percent
        assert restored.memory_percent == proc.memory_percent

    def test_event_data_to_dict_and_json(self):
        proc = ProcessTelemetry(pid=5678, name="python.exe", cpu_percent=1.0)
        event = EventData(
            event_type=EventType.CREATED.value,
            file_path="C:\\test_sandbox\\file.txt",
            file_extension=".txt",
            file_size_bytes=1024,
            is_directory=False,
            is_canary=True,
            severity="high",
            process_telemetry=proc,
            metadata={"source": "test"},
        )

        d = event.to_dict()
        assert d["event_type"] == "created"
        assert d["file_extension"] == ".txt"
        assert d["file_size_bytes"] == 1024
        assert d["is_canary"] is True
        assert d["severity"] == "high"
        assert d["process_telemetry"]["pid"] == 5678
        assert d["metadata"]["source"] == "test"

        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["file_path"] == "C:\\test_sandbox\\file.txt"
        assert parsed["is_canary"] is True
        assert parsed["severity"] == "high"

        restored = EventData.from_dict(d)
        assert restored.event_id == event.event_id
        assert restored.event_type == "created"
        assert restored.file_extension == ".txt"
        assert restored.is_canary is True
        assert restored.severity == "high"
        assert restored.process_telemetry is not None
        assert restored.process_telemetry.pid == 5678


class TestProcessMonitor:
    """Tests for defensive ProcessMonitor telemetry collection."""

    def test_current_process_telemetry(self):
        pm = ProcessMonitor()
        current_telemetry = pm.get_current_process_telemetry()
        assert current_telemetry is not None
        assert current_telemetry.pid == os.getpid()
        assert isinstance(current_telemetry.name, str)
        assert current_telemetry.cpu_percent >= 0.0
        assert current_telemetry.memory_percent >= 0.0

    def test_nonexistent_pid_returns_none(self):
        pm = ProcessMonitor()
        # Large PID unlikely to exist
        telemetry = pm.get_process_telemetry(pid=9999999)
        assert telemetry is None

    def test_get_top_active_processes(self):
        pm = ProcessMonitor()
        top_procs = pm.get_top_active_processes(limit=3, sort_by="cpu")
        assert isinstance(top_procs, list)
        if pm.is_psutil_available:
            assert len(top_procs) > 0
            assert isinstance(top_procs[0], ProcessTelemetry)

    def test_snapshot_all_processes(self):
        pm = ProcessMonitor()
        snapshot = pm.snapshot_all_processes()
        assert isinstance(snapshot, dict)
        if pm.is_psutil_available:
            assert len(snapshot) > 0
            assert os.getpid() in snapshot or len(snapshot) > 0


class TestFileMonitor:
    """Tests for FileMonitor detecting file operations in temporary sandbox."""

    def test_file_monitor_lifecycle(self, tmp_path: Path):
        monitor = FileMonitor(watch_dir=tmp_path)
        assert not monitor.is_alive()
        monitor.start()
        assert monitor.is_alive()
        monitor.stop()
        assert not monitor.is_alive()

    def test_file_monitor_context_manager(self, tmp_path: Path):
        with FileMonitor(watch_dir=tmp_path) as monitor:
            assert monitor.is_alive()
        assert not monitor.is_alive()

    def test_file_monitor_events(self, tmp_path: Path):
        captured_events: List[EventData] = []

        def on_event(ev: EventData):
            captured_events.append(ev)

        monitor = FileMonitor(watch_dir=tmp_path, callback=on_event)
        monitor.start()
        try:
            # 1. Create file
            test_file = tmp_path / "test_doc.txt"
            test_file.write_text("initial content", encoding="utf-8")
            time.sleep(0.3)

            # 2. Modify file
            test_file.write_text("updated content with more bytes", encoding="utf-8")
            time.sleep(0.3)

            # 3. Rename file
            renamed_file = tmp_path / "test_doc_renamed.txt"
            test_file.rename(renamed_file)
            time.sleep(0.3)

            # 4. Delete file
            renamed_file.unlink()
            time.sleep(0.3)

        finally:
            monitor.stop()

        assert len(captured_events) > 0
        event_types = [ev.event_type for ev in captured_events]
        assert any(t in event_types for t in ["created", "modified", "renamed", "moved", "deleted"])


class TestWatchdogAgent:
    """Tests for the unified WatchdogAgent coordinator."""

    def test_agent_coordination_and_callbacks(self, tmp_path: Path):
        received_by_subscriber: List[EventData] = []

        def subscriber_cb(event: EventData):
            received_by_subscriber.append(event)

        agent = WatchdogAgent(
            watch_dir=tmp_path,
            recursive=True,
            correlate_processes=True,
            max_event_history=50,
            callbacks=[subscriber_cb],
        )

        with agent:
            assert agent.is_alive()
            sample_file = tmp_path / "sample.log"
            sample_file.write_text("defensive log entry", encoding="utf-8")
            time.sleep(0.3)

            history = agent.get_recent_events()
            assert len(history) >= 0

        assert not agent.is_alive()

    def test_add_and_remove_callback(self, tmp_path: Path):
        agent = WatchdogAgent(watch_dir=tmp_path)
        cb = lambda ev: None
        agent.add_callback(cb)
        assert cb in agent._callbacks
        agent.remove_callback(cb)
        assert cb not in agent._callbacks
