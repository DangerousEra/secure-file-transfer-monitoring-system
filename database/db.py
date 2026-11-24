"""Small, parameterized SQLite repository used by the application."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from database.models import FileEvent


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self, schema_path: Path) -> None:
        with self.connection() as conn:
            conn.executescript(schema_path.read_text(encoding="utf-8"))

    @staticmethod
    def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows]

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connection() as conn:
            return self._rows(conn.execute(sql, params).fetchall())

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self.connection() as conn:
            return conn.execute(sql, params).lastrowid

    def add_event(self, event: FileEvent, event_key: str, timestamp: str | None = None) -> int | None:
        timestamp = timestamp or utcnow()
        try:
            return self.execute(
                """INSERT INTO file_events (event_key,timestamp,event_type,source_path,destination_path,
                   file_name,extension,file_size,file_hash,username,process_name,classification,risk_level,
                   authorization_status,is_directory,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_key, timestamp, event.event_type, event.source_path, event.destination_path,
                 event.file_name, event.extension, event.file_size, event.file_hash, event.username,
                 event.process_name, event.classification, event.risk_level, event.authorization_status,
                 int(event.is_directory), json.dumps(event.details)),
            )
        except sqlite3.IntegrityError:
            return None

    def add_alert(self, *, dedupe_key: str, title: str, description: str, severity: str,
                  detection_rule: str, related_event_id: int | None = None, related_file: str | None = None,
                  source_path: str | None = None, destination_path: str | None = None) -> int | None:
        try:
            return self.execute(
                """INSERT INTO security_alerts (dedupe_key,timestamp,title,description,related_event_id,
                   related_file,source_path,destination_path,severity,detection_rule) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (dedupe_key, utcnow(), title, description, related_event_id, related_file, source_path,
                 destination_path, severity, detection_rule),
            )
        except sqlite3.IntegrityError:
            return None

    def set_setting(self, key: str, value: str) -> None:
        self.execute("""INSERT INTO application_settings(key,value,updated_at) VALUES(?,?,?)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                     (key, value, utcnow()))

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM application_settings WHERE key=?", (key,))
        return row["value"] if row else default
