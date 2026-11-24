"""Safe SHA256 integrity operations. The module only reads monitored files."""
from __future__ import annotations

import hashlib
from pathlib import Path

from config import Config
from database.db import Database, utcnow


class IntegrityService:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def sha256(path: str | Path, chunk_size: int = Config.HASH_CHUNK_SIZE) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def protect_file(self, path: str | Path, notes: str = "") -> dict:
        file_path = Path(path).resolve()
        if not file_path.is_file():
            raise ValueError("Only existing files can be protected.")
        current_hash = self.sha256(file_path)
        now = utcnow()
        self.db.execute(
            """INSERT INTO integrity_records(file_path,file_name,baseline_hash,current_hash,status,protected,
               last_verified_at,notes,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(file_path) DO UPDATE SET baseline_hash=excluded.baseline_hash,
               current_hash=excluded.current_hash,status='Verified',protected=1,last_verified_at=excluded.last_verified_at,
               notes=excluded.notes,updated_at=excluded.updated_at""",
            (str(file_path), file_path.name, current_hash, current_hash, "Verified", 1, now, notes, now),
        )
        return self.get_record(str(file_path)) or {}

    def get_record(self, path: str) -> dict | None:
        return self.db.one("SELECT * FROM integrity_records WHERE file_path=?", (str(Path(path).resolve()),))

    def verify(self, path: str | Path) -> dict | None:
        record = self.get_record(str(path))
        if not record:
            return None
        file_path = Path(record["file_path"])
        now = utcnow()
        if not file_path.exists():
            status, current_hash = "Deleted", None
        else:
            try:
                current_hash = self.sha256(file_path)
                status = "Verified" if current_hash == record["baseline_hash"] else "Mismatch"
            except (OSError, PermissionError):
                status, current_hash = "Pending Verification", None
        self.db.execute("UPDATE integrity_records SET current_hash=?, status=?, last_verified_at=?, updated_at=? WHERE id=?",
                        (current_hash, status, now, now, record["id"]))
        return self.db.one("SELECT * FROM integrity_records WHERE id=?", (record["id"],))

    def verify_all(self) -> list[dict]:
        return [item for row in self.db.query("SELECT file_path FROM integrity_records WHERE protected=1")
                if (item := self.verify(row["file_path"]))]

    def remove(self, record_id: int) -> bool:
        return bool(self.db.execute("DELETE FROM integrity_records WHERE id=?", (record_id,)))
