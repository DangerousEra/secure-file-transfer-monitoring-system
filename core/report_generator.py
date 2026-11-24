"""Exports database-backed audit reports as CSV and PDF."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class ReportGenerator:
    def __init__(self, db, report_dir: Path):
        self.db = db
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def summary(self, date_from: str | None = None, date_to: str | None = None) -> dict:
        where, params = self._period_clause(date_from, date_to)
        events = self.db.query(f"SELECT * FROM file_events {where} ORDER BY timestamp DESC", params)
        alerts = self.db.query(f"SELECT * FROM security_alerts {where} ORDER BY timestamp DESC", params)
        counts = {name: sum(1 for event in events if event["event_type"] == name) for name in ("created", "modified", "deleted", "moved")}
        alert_counts = {severity: sum(1 for alert in alerts if alert["severity"] == severity)
                        for severity in ("Critical", "High", "Medium", "Low", "Informational")}
        return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "date_from": date_from,
                "date_to": date_to, "events": events, "alerts": alerts, "total_events": len(events),
                "counts": counts, "alert_counts": alert_counts,
                "sensitive_events": sum(1 for event in events if event["classification"] != "Normal"),
                "integrity_violations": self.db.one("SELECT COUNT(*) AS count FROM integrity_records WHERE status IN ('Mismatch','Deleted')")["count"]}

    def csv(self, date_from: str | None = None, date_to: str | None = None) -> Path:
        report = self.summary(date_from, date_to)
        path = self.report_dir / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.csv"
        columns = ["record_type", "timestamp", "event_type", "file_name", "source_path", "destination_path",
                   "classification", "risk_level", "authorization_status", "file_hash", "title", "severity",
                   "status", "detection_rule", "description"]
        with path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=columns)
            writer.writeheader()
            rows = [{"record_type": "event", **{key: event.get(key) for key in columns if key in event}}
                    for event in report["events"]]
            rows.extend({"record_type": "alert", "timestamp": alert["timestamp"],
                         "file_name": alert["related_file"], "source_path": alert["source_path"],
                         "destination_path": alert["destination_path"], "title": alert["title"],
                         "severity": alert["severity"], "status": alert["status"],
                         "detection_rule": alert["detection_rule"], "description": alert["description"]}
                        for alert in report["alerts"])
            writer.writerows({key: _csv_safe(value) for key, value in row.items()} for row in rows)
        return path

    def pdf(self, date_from: str | None = None, date_to: str | None = None) -> Path:
        report = self.summary(date_from, date_to)
        path = self.report_dir / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.pdf"
        styles = getSampleStyleSheet()
        story = [Paragraph("Secure File Transfer Monitoring System", styles["Title"]),
                 Paragraph("Database-backed audit report", styles["Heading2"]),
                 Paragraph(f"Generated: {report['generated_at']}", styles["Normal"]), Spacer(1, 0.4 * cm)]
        data = [["Metric", "Value"], ["Total events", str(report["total_events"])], ["Sensitive activity", str(report["sensitive_events"])],
                ["Created", str(report["counts"]["created"])], ["Modified", str(report["counts"]["modified"])],
                ["Deleted", str(report["counts"]["deleted"])], ["Moved", str(report["counts"]["moved"])],
                ["Integrity violations", str(report["integrity_violations"])], ["Alerts", str(len(report["alerts"]))]]
        data.extend([f"{severity} alerts", str(count)] for severity, count in report["alert_counts"].items())
        table = Table(data, colWidths=[8 * cm, 5 * cm])
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a43")),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eaf2f8")])]))
        story += [table, Spacer(1, 0.5 * cm), Paragraph("Recent activity", styles["Heading2"])]
        rows = [["Time", "Type", "File", "Risk"]] + [[event["timestamp"][:19], event["event_type"], event["file_name"][:35], event["risk_level"]] for event in report["events"][:20]]
        event_table = Table(rows, colWidths=[3.3 * cm, 2.2 * cm, 8 * cm, 2.2 * cm])
        event_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#244a68")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                         ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(event_table)
        story += [Spacer(1, 0.5 * cm), Paragraph("Recent alerts", styles["Heading2"])]
        alert_rows = [["Time", "Severity", "Alert", "Status", "Rule"]] + [
            [alert["timestamp"][:19], alert["severity"], alert["title"][:45], alert["status"], alert["detection_rule"][:30]]
            for alert in report["alerts"][:20]
        ]
        alert_table = Table(alert_rows, colWidths=[2.6 * cm, 2.1 * cm, 6.2 * cm, 2.6 * cm, 4.0 * cm], repeatRows=1)
        alert_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#244a68")),
                                         ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                         ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                                         ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(alert_table)
        SimpleDocTemplate(str(path), pagesize=A4, rightMargin=1.4 * cm, leftMargin=1.4 * cm, topMargin=1.4 * cm).build(story)
        return path

    @staticmethod
    def _period_clause(date_from: str | None, date_to: str | None) -> tuple[str, tuple]:
        parts, params = [], []
        if date_from:
            parts.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            parts.append("timestamp <= ?")
            params.append(date_to + "T23:59:59+00:00")
        return ("WHERE " + " AND ".join(parts) if parts else "", tuple(params))


def _csv_safe(value):
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
