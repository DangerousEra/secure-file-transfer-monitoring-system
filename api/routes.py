"""Browser pages and JSON endpoints. All mutations require a same-session CSRF token."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, render_template, request, send_file, session

from core.report_generator import ReportGenerator

bp = Blueprint("sftms", __name__)
VALID_SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}


def services() -> dict[str, Any]:
    return current_app.extensions["sftms"]


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@bp.before_app_request
def require_csrf() -> Response | None:
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if current_app.config.get("CLOUD_DEMO"):
            return jsonify(error="The hosted demonstration is read-only."), 403
        supplied = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("csrf_token")
        if not supplied or not secrets.compare_digest(str(session.get("csrf_token", "")), str(supplied)):
            return jsonify(error="A valid CSRF token is required."), 403
    return None


@bp.context_processor
def inject_context() -> dict:
    return {"csrf_token": csrf_token(), "cloud_demo": current_app.config.get("CLOUD_DEMO", False)}


@bp.get("/")
def dashboard_page():
    return render_template("dashboard.html", page="dashboard")


@bp.get("/activity")
def activity_page():
    return render_template("activity_logs.html", page="activity")


@bp.get("/alerts")
def alerts_page():
    return render_template("alerts.html", page="alerts")


@bp.get("/integrity")
def integrity_page():
    return render_template("integrity.html", page="integrity")


@bp.get("/policies")
def policies_page():
    return render_template("policies.html", page="policies")


@bp.get("/reports")
def reports_page():
    return render_template("reports.html", page="reports")


@bp.get("/settings")
def settings_page():
    return render_template("settings.html", page="settings")


@bp.get("/api/csrf-token")
def token_endpoint():
    return jsonify(token=csrf_token())


@bp.get("/api/dashboard")
def dashboard_api():
    db = services()["db"]
    today = datetime.now(timezone.utc).date().isoformat()
    stats = {
        "total_events": db.one("SELECT COUNT(*) AS count FROM file_events")["count"],
        "sensitive_events": db.one("SELECT COUNT(*) AS count FROM file_events WHERE classification != 'Normal'")["count"],
        "alerts": db.one("SELECT COUNT(*) AS count FROM security_alerts WHERE status IN ('New','Investigating')")["count"],
        "integrity_violations": db.one("SELECT COUNT(*) AS count FROM integrity_records WHERE status IN ('Mismatch','Deleted')")["count"],
        "directories": db.one("SELECT COUNT(*) AS count FROM monitoring_directories WHERE enabled=1")["count"],
        "enabled_policies": db.one("SELECT COUNT(*) AS count FROM security_policies WHERE enabled=1")["count"],
    }
    by_type = db.query("SELECT event_type AS label, COUNT(*) AS value FROM file_events GROUP BY event_type")
    by_severity = db.query("SELECT severity AS label, COUNT(*) AS value FROM security_alerts GROUP BY severity")
    by_integrity = db.query("SELECT status AS label, COUNT(*) AS value FROM integrity_records GROUP BY status")
    trend = db.query("SELECT substr(timestamp,1,10) AS label, COUNT(*) AS value FROM file_events GROUP BY substr(timestamp,1,10) ORDER BY label DESC LIMIT 7")
    return jsonify(stats=stats, monitoring=services()["monitor"].status(), recent_events=db.query("SELECT * FROM file_events ORDER BY timestamp DESC LIMIT 8"),
                   latest_alert=db.one("SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT 1"),
                   charts={"events_by_type": by_type, "alerts_by_severity": by_severity, "integrity": by_integrity, "activity": list(reversed(trend))}, today=today)


def _page_args() -> tuple[int, int]:
    try:
        page = max(1, int(request.args.get("page", "1")))
        per_page = min(100, max(5, int(request.args.get("per_page", "20"))))
    except ValueError:
        page, per_page = 1, 20
    return page, per_page


@bp.get("/api/events")
def list_events():
    db = services()["db"]
    page, per_page = _page_args()
    clauses, params = [], []
    filters = {"q": "file_name", "event_type": "event_type", "risk_level": "risk_level"}
    for name, column in filters.items():
        value = request.args.get(name, "").strip()
        if value:
            clauses.append(f"{column} LIKE ?")
            params.append(f"%{value}%" if name == "q" else value)
    date_from, date_to = request.args.get("date_from", ""), request.args.get("date_to", "")
    if date_from:
        clauses.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("timestamp <= ?")
        params.append(date_to + "T23:59:59+00:00")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    count = db.one(f"SELECT COUNT(*) AS count FROM file_events{where}", tuple(params))["count"]
    rows = db.query(f"SELECT * FROM file_events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", tuple(params + [per_page, (page - 1) * per_page]))
    return jsonify(items=rows, page=page, per_page=per_page, total=count)


@bp.get("/api/events/<int:event_id>")
def event_detail(event_id: int):
    event = services()["db"].one("SELECT * FROM file_events WHERE id=?", (event_id,))
    return jsonify(event) if event else (jsonify(error="Event not found"), 404)


@bp.get("/api/alerts")
def list_alerts():
    db = services()["db"]
    page, per_page = _page_args()
    clauses, params = [], []
    for name in ("severity", "status"):
        if value := request.args.get(name, "").strip():
            clauses.append(f"{name}=?")
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = db.one(f"SELECT COUNT(*) AS count FROM security_alerts{where}", tuple(params))["count"]
    rows = db.query(f"SELECT * FROM security_alerts{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?", tuple(params + [per_page, (page - 1) * per_page]))
    return jsonify(items=rows, page=page, per_page=per_page, total=total)


@bp.patch("/api/alerts/<int:alert_id>")
def update_alert(alert_id: int):
    data = request.get_json(force=True)
    try:
        changed = services()["alerts"].update_status(alert_id, str(data.get("status", "")), str(data.get("investigation_notes", ""))[:4000])
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(updated=changed) if changed else (jsonify(error="Alert not found"), 404)


@bp.get("/api/integrity")
def list_integrity():
    return jsonify(items=services()["db"].query("SELECT * FROM integrity_records ORDER BY updated_at DESC"))


@bp.post("/api/integrity")
def add_integrity():
    data = request.get_json(force=True)
    try:
        record = services()["integrity"].protect_file(_safe_file_path(data.get("path", "")), str(data.get("notes", ""))[:1000])
    except (ValueError, OSError, PermissionError) as error:
        return jsonify(error=str(error)), 400
    return jsonify(record), 201


@bp.post("/api/integrity/verify")
def verify_integrity():
    records = services()["integrity"].verify_all()
    for record in records:
        services()["alerts"].integrity_alert(None, record)
    return jsonify(items=records)


@bp.delete("/api/integrity/<int:record_id>")
def delete_integrity(record_id: int):
    services()["db"].execute("DELETE FROM integrity_records WHERE id=?", (record_id,))
    return jsonify(deleted=True)


@bp.get("/api/policies")
def list_policies():
    rows = services()["db"].query("SELECT * FROM security_policies ORDER BY created_at DESC")
    return jsonify(items=[_decode_policy(row) for row in rows])


@bp.post("/api/policies")
def create_policy():
    data = request.get_json(force=True)
    name = str(data.get("name", "")).strip()
    if not name or len(name) > 100:
        return jsonify(error="Policy name is required and must be under 100 characters."), 400
    severity = str(data.get("severity", "Medium"))
    if severity not in VALID_SEVERITIES:
        return jsonify(error="Invalid severity"), 400
    try:
        policy_id = services()["db"].execute(
            """INSERT INTO security_policies(name,description,source_directory,allowed_destinations,restricted_destinations,extensions,severity,enabled,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (name, str(data.get("description", ""))[:1000], str(data.get("source_directory", "")), json.dumps(_string_list(data.get("allowed_destinations", []))),
             json.dumps(_string_list(data.get("restricted_destinations", []))), json.dumps(_string_list(data.get("extensions", []))), severity,
             int(bool(data.get("enabled", True))), datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
    except Exception:
        return jsonify(error="A policy with that name already exists."), 409
    return jsonify(id=policy_id), 201


@bp.put("/api/policies/<int:policy_id>")
def update_policy(policy_id: int):
    data = request.get_json(force=True)
    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        return jsonify(error="Invalid severity"), 400
    existing = services()["db"].one("SELECT * FROM security_policies WHERE id=?", (policy_id,))
    if not existing:
        return jsonify(error="Policy not found"), 404
    fields = {"name": str(data.get("name", existing["name"]))[:100], "description": str(data.get("description", existing["description"]))[:1000],
              "source_directory": str(data.get("source_directory", existing["source_directory"])), "severity": data.get("severity", existing["severity"]),
              "enabled": int(bool(data.get("enabled", bool(existing["enabled"]))))}
    for key in ("allowed_destinations", "restricted_destinations", "extensions"):
        fields[key] = json.dumps(_string_list(data[key])) if key in data else existing[key]
    services()["db"].execute("""UPDATE security_policies SET name=?,description=?,source_directory=?,allowed_destinations=?,restricted_destinations=?,extensions=?,severity=?,enabled=?,updated_at=? WHERE id=?""",
                             (*fields.values(), datetime.now(timezone.utc).isoformat(timespec="seconds"), policy_id))
    return jsonify(updated=True)


@bp.delete("/api/policies/<int:policy_id>")
def delete_policy(policy_id: int):
    services()["db"].execute("DELETE FROM security_policies WHERE id=?", (policy_id,))
    return jsonify(deleted=True)


@bp.get("/api/directories")
def list_directories():
    return jsonify(items=services()["db"].query("SELECT * FROM monitoring_directories ORDER BY label,path"))


@bp.post("/api/directories")
def add_directory():
    data = request.get_json(force=True)
    try:
        path = _safe_directory_path(data.get("path", ""))
    except ValueError as error:
        return jsonify(error=str(error)), 400
    label = str(data.get("label", "Monitored directory")).strip()[:100] or "Monitored directory"
    try:
        entry_id = services()["db"].execute("INSERT INTO monitoring_directories(path,label,enabled) VALUES(?,?,?)", (str(path), label, int(bool(data.get("enabled", True)))))
    except Exception:
        return jsonify(error="This directory already exists in the configuration."), 409
    return jsonify(id=entry_id), 201


@bp.delete("/api/directories/<int:directory_id>")
def delete_directory(directory_id: int):
    services()["db"].execute("DELETE FROM monitoring_directories WHERE id=?", (directory_id,))
    return jsonify(deleted=True)


@bp.post("/api/monitor/<action>")
def monitor_control(action: str):
    monitor = services()["monitor"]
    if action == "start": result = monitor.start()
    elif action == "stop": result = monitor.stop()
    elif action == "restart": result = monitor.restart()
    else: return jsonify(error="Unsupported monitoring action"), 404
    return jsonify(result)


@bp.post("/api/demo/setup")
def setup_demo():
    from demo import setup_demo_environment
    result = setup_demo_environment(services()["db"], Path(current_app.config["DEMO_DIR"]))
    return jsonify(result)


@bp.get("/api/reports/<fmt>")
def report_export(fmt: str):
    generator = ReportGenerator(services()["db"], Path(current_app.config["REPORT_DIR"]))
    date_from, date_to = request.args.get("date_from"), request.args.get("date_to")
    if fmt == "csv": path, mimetype = generator.csv(date_from, date_to), "text/csv"
    elif fmt == "pdf": path, mimetype = generator.pdf(date_from, date_to), "application/pdf"
    else: return jsonify(error="Use csv or pdf"), 404
    return send_file(path, as_attachment=True, download_name=path.name, mimetype=mimetype)


@bp.get("/api/settings")
def settings_api():
    db = services()["db"]
    return jsonify(monitor=services()["monitor"].status(), database=str(db.path), settings=db.query("SELECT * FROM application_settings ORDER BY key"))


def _safe_directory_path(value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A directory path is required.")
    path = Path(value).expanduser().resolve()
    if path == path.anchor or not path.is_dir():
        raise ValueError("Choose an existing non-root directory.")
    return path


def _safe_file_path(value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A file path is required.")
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Choose an existing file.")
    return path


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [part.strip() for part in value.split(",")]
    if not isinstance(value, list):
        return []
    return [str(part).strip() for part in value if str(part).strip()][:50]


def _decode_policy(policy: dict) -> dict:
    for key in ("allowed_destinations", "restricted_destinations", "extensions"):
        policy[key] = json.loads(policy[key])
    return policy
