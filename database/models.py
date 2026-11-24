"""Typed models shared by the monitoring and policy modules."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileEvent:
    event_type: str
    source_path: str | None
    destination_path: str | None
    file_name: str
    extension: str = ""
    file_size: int | None = None
    file_hash: str | None = None
    username: str = "unknown"
    process_name: str = "unavailable"
    classification: str = "Normal"
    risk_level: str = "Informational"
    authorization_status: str = "Requires Investigation"
    is_directory: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
