"""Classifies paths as normal or potentially sensitive using transparent rules."""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable


DEFAULT_SENSITIVE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".csv", ".sql", ".db", ".pem", ".key", ".env", ".conf"}


class FileClassifier:
    def __init__(self, db=None):
        self.db = db

    def classify(self, path: str | None) -> dict[str, str | bool]:
        if not path:
            return {"sensitive": False, "classification": "Normal", "risk_level": "Informational", "reason": "No file path"}
        file_path = Path(path)
        extension = file_path.suffix.lower()
        sensitive_dirs = self._sensitive_directories()
        directory_match = any(self._is_within(file_path, item["path"]) for item in sensitive_dirs)
        extension_match = extension in DEFAULT_SENSITIVE_EXTENSIONS
        sensitive = directory_match or extension_match
        if sensitive:
            level = "High" if extension in {".pem", ".key", ".env", ".db", ".sql"} else "Medium"
            reason = "Matches a configured sensitive directory" if directory_match else f"Uses configured sensitive extension {extension}"
            return {"sensitive": True, "classification": "Sensitive File Activity", "risk_level": level, "reason": reason}
        return {"sensitive": False, "classification": "Normal", "risk_level": "Informational", "reason": "No sensitivity rule matched"}

    def matches_patterns(self, path: str, patterns: Iterable[str]) -> bool:
        candidate = str(Path(path)).lower()
        return any(fnmatch.fnmatch(candidate, pattern.lower()) or fnmatch.fnmatch(Path(path).name.lower(), pattern.lower()) for pattern in patterns)

    def _sensitive_directories(self) -> list[dict]:
        if not self.db:
            return []
        return self.db.query("SELECT path FROM monitoring_directories WHERE label LIKE 'Sensitive%' AND enabled=1")

    @staticmethod
    def _is_within(path: Path, directory: str) -> bool:
        try:
            path.resolve().relative_to(Path(directory).resolve())
            return True
        except ValueError:
            return False
