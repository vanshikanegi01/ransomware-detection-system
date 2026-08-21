"""
File System Monitor for Windows Watchdog Agent (Member 1).

Monitors a target directory in real-time for file creations, modifications,
deletions, and renames/moves using the safe `watchdog` library. Collects
passive, non-destructive file telemetry.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Set

# Ensure project root is in sys.path when executed directly or imported in isolation
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.models import EventData, EventType

logger = logging.getLogger("watcher.file_monitor")

# Optional import of watchdog
try:
    from watchdog.events import (
        FileCreatedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileMovedEvent,
        FileSystemEvent,
        FileSystemEventHandler,
    )
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object
    FileSystemEvent = object


class _WatchdogHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Internal Watchdog FileSystemEventHandler translating OS events to EventData."""

    def __init__(self, callback: Callable[[EventData], None], ignore_patterns: Optional[List[str]] = None) -> None:
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.callback = callback
        self.ignore_patterns: List[str] = ignore_patterns or []

    def _should_ignore(self, path_str: str) -> bool:
        """Check if the given path matches any configured ignore patterns."""
        if not path_str:
            return True
        norm_path = path_str.replace("\\", "/").lower()
        for pattern in self.ignore_patterns:
            pat = pattern.replace("\\", "/").lower()
            if pat in norm_path:
                return True
        return False

    def _extract_file_metadata(self, file_path_str: str) -> tuple[str, Optional[int]]:
        """
        Safely extract extension and file size in bytes.
        Returns (extension, size_bytes). Suppresses file locking/deletion exceptions.
        """
        try:
            path_obj = Path(file_path_str)
            ext = path_obj.suffix.lower()
        except Exception:
            ext = ""

        size_bytes: Optional[int] = None
        try:
            if os.path.exists(file_path_str) and not os.path.isdir(file_path_str):
                size_bytes = os.path.getsize(file_path_str)
        except (FileNotFoundError, PermissionError, OSError):
            size_bytes = None
        except Exception as e:
            logger.debug("Non-fatal error reading file size for %s: %s", file_path_str, e)
            size_bytes = None

        return ext, size_bytes

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file/directory creation."""
        if self._should_ignore(event.src_path):
            return
        ext, size = self._extract_file_metadata(event.src_path)
        data = EventData(
            event_type=EventType.CREATED.value,
            file_path=os.path.abspath(event.src_path),
            file_extension=ext,
            file_size_bytes=size,
            is_directory=event.is_directory,
        )
        self.callback(data)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file/directory modification."""
        if self._should_ignore(event.src_path):
            return
        ext, size = self._extract_file_metadata(event.src_path)
        data = EventData(
            event_type=EventType.MODIFIED.value,
            file_path=os.path.abspath(event.src_path),
            file_extension=ext,
            file_size_bytes=size,
            is_directory=event.is_directory,
        )
        self.callback(data)

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Handle file/directory deletion."""
        if self._should_ignore(event.src_path):
            return
        try:
            ext = Path(event.src_path).suffix.lower()
        except Exception:
            ext = ""

        data = EventData(
            event_type=EventType.DELETED.value,
            file_path=os.path.abspath(event.src_path),
            file_extension=ext,
            file_size_bytes=None,
            is_directory=event.is_directory,
        )
        self.callback(data)

    def on_moved(self, event: FileMovedEvent) -> None:
        """Handle file/directory rename or move."""
        if self._should_ignore(event.src_path) and self._should_ignore(event.dest_path):
            return
        ext, size = self._extract_file_metadata(event.dest_path)
        data = EventData(
            event_type=EventType.RENAMED.value if not event.is_directory else EventType.MOVED.value,
            file_path=os.path.abspath(event.src_path),
            dest_path=os.path.abspath(event.dest_path),
            file_extension=ext,
            file_size_bytes=size,
            is_directory=event.is_directory,
        )
        self.callback(data)


class _FallbackPollingMonitor:
    """
    Safe pure-Python polling monitor fallback used if watchdog is not installed.
    Monitors directory state snapshots periodically.
    """

    def __init__(
        self,
        watch_dir: Path,
        recursive: bool,
        callback: Callable[[EventData], None],
        ignore_patterns: Optional[List[str]] = None,
        poll_interval: float = 0.5,
    ) -> None:
        self.watch_dir = watch_dir
        self.recursive = recursive
        self.callback = callback
        self.ignore_patterns = ignore_patterns or []
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_state: dict[str, tuple[float, int]] = {}  # path -> (mtime, size)

    def _should_ignore(self, path_str: str) -> bool:
        norm_path = path_str.replace("\\", "/").lower()
        for pattern in self.ignore_patterns:
            if pattern.replace("\\", "/").lower() in norm_path:
                return True
        return False

    def _scan_files(self) -> dict[str, tuple[float, int]]:
        state: dict[str, tuple[float, int]] = {}
        try:
            if self.recursive:
                iterator = self.watch_dir.rglob("*")
            else:
                iterator = self.watch_dir.glob("*")

            for item in iterator:
                try:
                    str_path = str(item.resolve())
                    if self._should_ignore(str_path):
                        continue
                    if item.is_file():
                        stat = item.stat()
                        state[str_path] = (stat.st_mtime, stat.st_size)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
        except Exception as e:
            logger.debug("Error during fallback scan: %s", e)
        return state

    def _run_loop(self) -> None:
        self._known_state = self._scan_files()
        while self._running:
            time.sleep(self.poll_interval)
            if not self._running:
                break
            current_state = self._scan_files()

            # Detect additions and modifications
            for path_str, (mtime, size) in current_state.items():
                if path_str not in self._known_state:
                    self.callback(
                        EventData(
                            event_type=EventType.CREATED.value,
                            file_path=path_str,
                            file_extension=Path(path_str).suffix.lower(),
                            file_size_bytes=size,
                            is_directory=False,
                        )
                    )
                elif self._known_state[path_str] != (mtime, size):
                    self.callback(
                        EventData(
                            event_type=EventType.MODIFIED.value,
                            file_path=path_str,
                            file_extension=Path(path_str).suffix.lower(),
                            file_size_bytes=size,
                            is_directory=False,
                        )
                    )

            # Detect deletions
            for path_str in list(self._known_state.keys()):
                if path_str not in current_state:
                    self.callback(
                        EventData(
                            event_type=EventType.DELETED.value,
                            file_path=path_str,
                            file_extension=Path(path_str).suffix.lower(),
                            file_size_bytes=None,
                            is_directory=False,
                        )
                    )

            self._known_state = current_state

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="FallbackFileMonitorThread")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def is_alive(self) -> bool:
        return self._running and (self._thread.is_alive() if self._thread else False)


class FileMonitor:
    """
    High-level File System Monitor.
    
    Monitors a specified directory for creation, modification, deletion,
    and rename/move operations. Dispatches safe `EventData` instances to
    registered callbacks.
    """

    def __init__(
        self,
        watch_dir: str | Path,
        callback: Optional[Callable[[EventData], None]] = None,
        recursive: bool = True,
        ignore_patterns: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the FileMonitor.

        Args:
            watch_dir: Path to directory to monitor.
            callback: Callable invoked whenever an EventData is captured.
            recursive: Whether to recursively monitor child directories.
            ignore_patterns: List of substring/path patterns to ignore.
        """
        self.watch_dir = Path(watch_dir).resolve()
        self.callback = callback or (lambda event: None)
        self.recursive = recursive
        self.ignore_patterns = ignore_patterns or [".git", "__pycache__", ".pytest_cache", ".venv", ".tmp"]
        self._observer: Optional[Observer] = None
        self._fallback_monitor: Optional[_FallbackPollingMonitor] = None
        self._is_active = False
        self._lock = threading.Lock()

    def set_callback(self, callback: Callable[[EventData], None]) -> None:
        """Update or register the event callback."""
        self.callback = callback

    def start(self) -> None:
        """Start monitoring the directory in the background."""
        with self._lock:
            if self._is_active:
                logger.warning("FileMonitor is already active on %s", self.watch_dir)
                return

            if not self.watch_dir.exists():
                raise FileNotFoundError(f"Watch directory does not exist: {self.watch_dir}")

            logger.info("Starting FileMonitor on %s (recursive=%s)", self.watch_dir, self.recursive)

            if WATCHDOG_AVAILABLE and Observer is not None:
                event_handler = _WatchdogHandler(
                    callback=self._dispatch_event,
                    ignore_patterns=self.ignore_patterns,
                )
                self._observer = Observer()
                self._observer.schedule(event_handler, str(self.watch_dir), recursive=self.recursive)
                self._observer.start()
            else:
                logger.info("Watchdog library not installed. Using safe polling fallback engine.")
                self._fallback_monitor = _FallbackPollingMonitor(
                    watch_dir=self.watch_dir,
                    recursive=self.recursive,
                    callback=self._dispatch_event,
                    ignore_patterns=self.ignore_patterns,
                )
                self._fallback_monitor.start()

            self._is_active = True

    def _dispatch_event(self, event: EventData) -> None:
        """Internal dispatch to user callback with exception containment."""
        try:
            self.callback(event)
        except Exception as e:
            logger.error("Error in FileMonitor callback: %s", e, exc_info=True)

    def stop(self) -> None:
        """Stop file monitoring gracefully."""
        with self._lock:
            if not self._is_active:
                return

            logger.info("Stopping FileMonitor on %s", self.watch_dir)
            if self._observer is not None:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=2.0)
                except Exception as e:
                    logger.debug("Error while stopping watchdog observer: %s", e)
                finally:
                    self._observer = None

            if self._fallback_monitor is not None:
                try:
                    self._fallback_monitor.stop()
                except Exception as e:
                    logger.debug("Error while stopping fallback monitor: %s", e)
                finally:
                    self._fallback_monitor = None

            self._is_active = False

    def is_alive(self) -> bool:
        """Check if the monitor is currently running."""
        with self._lock:
            if not self._is_active:
                return False
            if self._observer is not None:
                return self._observer.is_alive()
            if self._fallback_monitor is not None:
                return self._fallback_monitor.is_alive()
            return False

    def __enter__(self) -> FileMonitor:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
