"""
Unit and Integration Tests for Canary Monitoring (Member 1 - TRINETRA).

Verifies CanaryMonitor decoy file deployment, cleanup, detection, and tagging
across CREATED, MODIFIED, RENAMED, and DELETED operations with high severity.
"""

import time
from pathlib import Path
from typing import List

import pytest

from watcher import (
    CanaryMonitor,
    EventData,
    EventType,
    WatchdogAgent,
)


class TestCanaryMonitor:
    """Tests for CanaryMonitor component."""

    def test_canary_deployment_and_cleanup(self, tmp_path: Path):
        monitor = CanaryMonitor(canary_dir=tmp_path)
        deployed = monitor.deploy_canaries(target_dir=tmp_path)

        assert len(deployed) > 0
        for canary_path in deployed:
            assert canary_path.exists()
            assert canary_path.is_file()
            content = canary_path.read_text(encoding="utf-8")
            assert "TRINETRA CANARY DECOY FILE" in content
            assert monitor.is_canary_path(canary_path)

        # Cleanup
        removed_count = monitor.cleanup_canaries(target_dir=tmp_path)
        assert removed_count == len(deployed)
        for canary_path in deployed:
            assert not canary_path.exists()

    def test_is_canary_path_matching(self, tmp_path: Path):
        monitor = CanaryMonitor(canary_dir=tmp_path)

        # 1. Registered exact path
        custom_file = tmp_path / "custom_decoy.bin"
        monitor.register_canary_file(custom_file)
        assert monitor.is_canary_path(custom_file)

        # 2. Known default filename
        default_canary = tmp_path / "!_canary_01.docx"
        assert monitor.is_canary_path(default_canary)

        # 3. Pattern match
        pattern_file = tmp_path / "subfolder" / "finance_canary_data.txt"
        assert monitor.is_canary_path(pattern_file)

        # 4. Normal non-canary file
        normal_file = tmp_path / "regular_document.docx"
        assert not monitor.is_canary_path(normal_file)

    def test_inspect_and_tag_event_on_canary(self, tmp_path: Path):
        monitor = CanaryMonitor(canary_dir=tmp_path)
        canary_file = tmp_path / "!_canary_01.docx"

        event = EventData(
            event_type=EventType.MODIFIED.value,
            file_path=str(canary_file.resolve()),
            file_extension=".docx",
            file_size_bytes=512,
        )

        assert not event.is_canary
        assert event.severity == "normal"

        tagged_event = monitor.inspect_and_tag_event(event)
        assert tagged_event.is_canary is True
        assert tagged_event.severity == "high"
        assert tagged_event.metadata.get("canary_alert") is True
        assert tagged_event.metadata.get("canary_trigger_event") == "modified"

    def test_inspect_and_tag_event_on_regular_file(self, tmp_path: Path):
        monitor = CanaryMonitor(canary_dir=tmp_path)
        normal_file = tmp_path / "normal_spreadsheet.xlsx"

        event = EventData(
            event_type=EventType.MODIFIED.value,
            file_path=str(normal_file.resolve()),
            file_extension=".xlsx",
            file_size_bytes=2048,
        )

        tagged_event = monitor.inspect_and_tag_event(event)
        assert tagged_event.is_canary is False
        assert tagged_event.severity == "normal"
        assert "canary_alert" not in tagged_event.metadata

    def test_inspect_and_tag_event_on_dest_path(self, tmp_path: Path):
        monitor = CanaryMonitor(canary_dir=tmp_path)
        src_file = tmp_path / "test.txt"
        dest_canary = tmp_path / "!_canary_renamed.txt"

        event = EventData(
            event_type=EventType.RENAMED.value,
            file_path=str(src_file.resolve()),
            dest_path=str(dest_canary.resolve()),
            file_extension=".txt",
        )

        tagged_event = monitor.inspect_and_tag_event(event)
        assert tagged_event.is_canary is True
        assert tagged_event.severity == "high"
        assert tagged_event.metadata.get("canary_alert") is True

    def test_watchdog_agent_canary_integration(self, tmp_path: Path):
        received_events: List[EventData] = []

        def callback(ev: EventData):
            received_events.append(ev)

        agent = WatchdogAgent(
            watch_dir=tmp_path,
            recursive=True,
            enable_canary=True,
            callbacks=[callback],
        )

        # Deploy canary files inside sandbox
        deployed = agent.deploy_canaries(filenames=["!_canary_test.docx"])
        assert len(deployed) == 1
        canary_path = deployed[0]

        with agent:
            assert agent.is_alive()
            time.sleep(0.3)

            # 1. Modify canary file (simulating ransomware tampering)
            canary_path.write_text("TAMPERED CONTENT", encoding="utf-8")
            time.sleep(0.3)

            # 2. Rename canary file
            renamed_canary = tmp_path / "!_canary_test_renamed.docx"
            canary_path.rename(renamed_canary)
            time.sleep(0.3)

            # 3. Delete canary file
            renamed_canary.unlink()
            time.sleep(0.3)

        assert len(received_events) > 0
        canary_events = [e for e in received_events if e.is_canary]
        assert len(canary_events) > 0
        for ev in canary_events:
            assert ev.is_canary is True
            assert ev.severity == "high"
            assert ev.metadata.get("canary_alert") is True
