"""Explainable policy evaluation for potential data movement events."""
from __future__ import annotations

import json
from pathlib import Path

from database.models import FileEvent


class PolicyEngine:
    def __init__(self, db, classifier):
        self.db = db
        self.classifier = classifier

    def evaluate(self, event: FileEvent) -> dict:
        if event.event_type not in {"moved", "created", "modified", "deleted"}:
            return self._allowed("Not a file movement event")
        target = event.destination_path or event.source_path
        if not target:
            return self._allowed("No path available")
        sensitive = self.classifier.classify(event.source_path or target)["sensitive"]
        violations: list[dict] = []
        allowed_by_policy = False
        for policy in self.db.query("SELECT * FROM security_policies WHERE enabled=1"):
            decision = self._evaluate_policy(policy, event, bool(sensitive))
            if decision and decision.get("allowed"):
                allowed_by_policy = True
                continue
            if decision:
                violations.append(decision)
        if violations:
            highest = max(violations, key=lambda item: self._severity_weight(item["severity"]))
            return {"authorization_status": "Policy Violation", "classification": "Suspicious Movement",
                    "risk_level": highest["severity"], "violations": violations, "reason": highest["reason"]}
        if allowed_by_policy:
            return self._allowed("Destination is explicitly allowed by a configured policy")
        if sensitive and event.event_type == "moved":
            return {"authorization_status": "Requires Investigation", "classification": "Sensitive File Activity",
                    "risk_level": "Medium", "violations": [], "reason": "Sensitive movement did not match a configured policy"}
        return self._allowed("No enabled policy matched")

    def _evaluate_policy(self, policy: dict, event: FileEvent, sensitive: bool) -> dict | None:
        source = event.source_path or ""
        destination = event.destination_path or ""
        source_rule = policy["source_directory"]
        if source_rule and not self._within(source, source_rule):
            return None
        extensions = self._decode(policy["extensions"])
        if extensions and Path(event.file_name).suffix.lower() not in {str(v).lower() for v in extensions}:
            return None
        if not sensitive and not extensions:
            return None
        restricted = self._decode(policy["restricted_destinations"])
        allowed = self._decode(policy["allowed_destinations"])
        if any(self._matches(destination, pattern) for pattern in allowed):
            return {"allowed": True}
        if any(self._matches(destination, pattern) for pattern in restricted):
            return {"policy_id": policy["id"], "policy_name": policy["name"], "severity": policy["severity"],
                    "reason": f"Destination matches restricted rule in policy '{policy['name']}'"}
        return None

    @staticmethod
    def _decode(value: str) -> list[str]:
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []

    @staticmethod
    def _within(path: str, root: str) -> bool:
        try:
            Path(path).resolve().relative_to(Path(root).resolve())
            return True
        except (ValueError, OSError):
            return False

    @staticmethod
    def _matches(path: str, pattern: str) -> bool:
        if not path or not pattern:
            return False
        try:
            Path(path).expanduser().resolve().relative_to(Path(pattern).expanduser().resolve())
            return True
        except (ValueError, OSError):
            return False

    @staticmethod
    def _severity_weight(severity: str) -> int:
        return {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(severity, 0)

    @staticmethod
    def _allowed(reason: str) -> dict:
        return {"authorization_status": "Authorized", "classification": "Normal", "risk_level": "Informational", "violations": [], "reason": reason}
