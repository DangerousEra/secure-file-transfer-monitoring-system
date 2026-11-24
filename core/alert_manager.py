"""Alert creation, deduplication, and status management."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone


class AlertManager:
    def __init__(self, db):
        self.db = db

    def from_policy(self, event_id: int, event, policy_result: dict) -> int | None:
        if not policy_result.get("violations"):
            return None
        rule = policy_result["violations"][0]
        return self.create(event_id=event_id, title="Suspicious sensitive file movement",
                           description=policy_result["reason"], related_file=event.file_name,
                           source_path=event.source_path, destination_path=event.destination_path,
                           severity=policy_result["risk_level"], rule=rule["policy_name"])

    def integrity_alert(self, event_id: int | None, record: dict) -> int | None:
        if record["status"] not in {"Mismatch", "Deleted"}:
            return None
        title = "Protected file deleted" if record["status"] == "Deleted" else "File integrity mismatch"
        return self.create(event_id=event_id, title=title, description=f"Integrity verification returned {record['status']}.",
                           related_file=record["file_name"], source_path=record["file_path"], destination_path=None,
                           severity="High", rule="SHA256 integrity verification")

    def create(self, *, event_id: int | None, title: str, description: str, related_file: str,
               source_path: str | None, destination_path: str | None, severity: str, rule: str) -> int | None:
        bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        raw = "|".join([title, related_file or "", source_path or "", destination_path or "", rule, bucket])
        key = hashlib.sha256(raw.encode()).hexdigest()
        return self.db.add_alert(dedupe_key=key, title=title, description=description, severity=severity,
                                 detection_rule=rule, related_event_id=event_id, related_file=related_file,
                                 source_path=source_path, destination_path=destination_path)

    def update_status(self, alert_id: int, status: str, notes: str) -> bool:
        if status not in {"New", "Investigating", "Resolved", "False Positive"}:
            raise ValueError("Invalid alert status")
        self.db.execute("UPDATE security_alerts SET status=?, investigation_notes=?, updated_at=? WHERE id=?",
                        (status, notes, datetime.now(timezone.utc).isoformat(timespec="seconds"), alert_id))
        return self.db.one("SELECT id FROM security_alerts WHERE id=?", (alert_id,)) is not None
