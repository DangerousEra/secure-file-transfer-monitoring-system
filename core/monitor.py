"""Lifecycle management for background Watchdog observers."""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from watchdog.observers import Observer

from config import Config
from core.event_handler import SecurityEventHandler

LOGGER = logging.getLogger(__name__)


class MonitoringService:
    def __init__(self, db, classifier, policy_engine, integrity, alerts):
        self.db = db
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.integrity = integrity
        self.alerts = alerts
        self._observer: Observer | None = None
        self._lock = threading.RLock()

    @property
    def active(self) -> bool:
        return bool(self._observer and self._observer.is_alive())

    def start(self) -> dict:
        with self._lock:
            if self.active:
                return self.status()
            directories = self.db.query("SELECT * FROM monitoring_directories WHERE enabled=1")
            observer = Observer()
            watched = []
            handler = SecurityEventHandler(self.db, self.classifier, self.policy_engine, self.integrity, self.alerts,
                                           Config.BULK_EVENT_THRESHOLD, Config.BULK_EVENT_WINDOW_SECONDS)
            for item in directories:
                path = Path(item["path"])
                if path.is_dir():
                    observer.schedule(handler, str(path), recursive=True)
                    watched.append(str(path))
                else:
                    LOGGER.warning("Configured directory unavailable: %s", path)
            if watched:
                observer.start()
                self._observer = observer
            self.db.set_setting("monitoring_status", "running" if watched else "idle")
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            if self._observer:
                self._observer.stop()
                self._observer.join(timeout=5)
                self._observer = None
            self.db.set_setting("monitoring_status", "stopped")
            return self.status()

    def restart(self) -> dict:
        self.stop()
        return self.start()

    def status(self) -> dict:
        enabled = self.db.one("SELECT COUNT(*) AS count FROM monitoring_directories WHERE enabled=1")
        return {"running": self.active, "state": "running" if self.active else self.db.get_setting("monitoring_status", "stopped"),
                "configured_directories": enabled["count"] if enabled else 0}
