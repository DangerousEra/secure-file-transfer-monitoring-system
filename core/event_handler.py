"""Watchdog callback adapter that normalizes and persists filesystem events."""
from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler

from core.process_tracker import ProcessTracker
from database.models import FileEvent

LOGGER = logging.getLogger(__name__)


class SecurityEventHandler(FileSystemEventHandler):
    def __init__(self, db, classifier, policy_engine, integrity, alerts, bulk_threshold: int, bulk_window: int):
        super().__init__()
        self.db = db
        self.classifier = classifier
        self.policy_engine = policy_engine
        self.integrity = integrity
        self.alerts = alerts
        self.bulk_threshold = bulk_threshold
        self.bulk_window = bulk_window
        self._recent_signatures: dict[str, float] = {}
        self._recent_activity: deque[tuple[float, str]] = deque()

    def on_created(self, event: FileSystemEvent) -> None:
        self._record("created", event.src_path, None, event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._record("modified", event.src_path, None, event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._record("deleted", event.src_path, None, event.is_directory)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._record("moved", event.src_path, getattr(event, "dest_path", None), event.is_directory)

    def _record(self, event_type: str, source: str, destination: str | None, is_directory: bool) -> None:
        try:
            target = destination or source
            path = Path(target)
            signature = f"{event_type}|{source}|{destination or ''}|{is_directory}"
            now = time.monotonic()
            if now - self._recent_signatures.get(signature, 0) < 0.8:
                return
            self._recent_signatures[signature] = now
            self._recent_signatures = {key: value for key, value in self._recent_signatures.items() if now - value < 10}
            size, digest = self._metadata(path, event_type, is_directory)
            user, process = ProcessTracker.context()
            file_name = path.name or Path(source).name
            classification = self.classifier.classify(source or target)
            event = FileEvent(event_type=event_type, source_path=str(Path(source).resolve()),
                              destination_path=str(Path(destination).resolve()) if destination else None,
                              file_name=file_name, extension=path.suffix.lower(), file_size=size, file_hash=digest,
                              username=user, process_name=process, classification=str(classification["classification"]),
                              risk_level=str(classification["risk_level"]), is_directory=is_directory,
                              details={"sensitivity_reason": classification["reason"], "copy_inference": False})
            policy = self.policy_engine.evaluate(event)
            event.authorization_status = policy["authorization_status"]
            event.classification = policy["classification"] if policy["classification"] != "Normal" else event.classification
            event.risk_level = policy["risk_level"] if policy["risk_level"] != "Informational" else event.risk_level
            event_key = hashlib.sha256((signature + str(int(time.time()))).encode()).hexdigest()
            event_id = self.db.add_event(event, event_key)
            if not event_id:
                return
            self.alerts.from_policy(event_id, event, policy)
            self._check_integrity(event_id, source, destination, event_type, is_directory)
            self._check_bulk(event_id, event)
        except Exception as error:  # Monitoring must remain available after one bad event.
            LOGGER.exception("Could not process filesystem event: %s", error)
            self.alerts.create(event_id=None, title="Monitoring service error", description=str(error)[:500],
                               related_file=Path(source).name, source_path=source, destination_path=destination,
                               severity="Medium", rule="Event handler exception")

    @staticmethod
    def _metadata(path: Path, event_type: str, is_directory: bool) -> tuple[int | None, str | None]:
        if is_directory or event_type == "deleted" or not path.is_file():
            return None, None
        try:
            if path.stat().st_size > 100 * 1024 * 1024:
                return path.stat().st_size, None
            return path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            return None, None

    def _check_integrity(self, event_id: int, source: str, destination: str | None, event_type: str, is_directory: bool) -> None:
        if is_directory:
            return
        paths = [source] + ([destination] if destination else [])
        for candidate in paths:
            record = self.integrity.verify(candidate)
            if record:
                self.alerts.integrity_alert(event_id, record)

    def _check_bulk(self, event_id: int, event: FileEvent) -> None:
        target = event.destination_path or event.source_path
        if event.event_type not in {"created", "moved"} or event.is_directory or not target:
            return
        now = time.monotonic()
        destination_root = str(Path(target).parent)
        self._recent_activity.append((now, destination_root))
        while self._recent_activity and now - self._recent_activity[0][0] > self.bulk_window:
            self._recent_activity.popleft()
        count = sum(1 for _, path in self._recent_activity if path == destination_root)
        if count >= self.bulk_threshold:
            self.alerts.create(event_id=event_id, title="Suspicious bulk file activity",
                               description=f"{count} file events targeted {destination_root} within {self.bulk_window} seconds.",
                               related_file="Multiple files", source_path=destination_root,
                               destination_path=destination_root, severity="High", rule="Bulk activity threshold")
