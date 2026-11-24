import csv
import io

from app import create_app
from database.models import FileEvent


def test_dashboard_and_pages_return_success(client):
    for path in ("/", "/activity", "/alerts", "/integrity", "/policies", "/reports", "/settings"):
        assert client.get(path).status_code == 200
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    assert "stats" in response.get_json()


def test_csrf_blocks_mutation(client):
    assert client.post("/api/monitor/start", json={}).status_code == 403


def test_cloud_demo_is_read_only_and_sets_security_headers(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "CLOUD_DEMO": True,
                      "DATABASE_PATH": tmp_path / "cloud.db", "REPORT_DIR": tmp_path / "reports",
                      "DEMO_DIR": tmp_path / "demo"})
    client = app.test_client()
    token = client.get("/api/csrf-token").get_json()["token"]
    response = client.post("/api/demo/setup", headers={"X-CSRF-Token": token}, json={})
    assert response.status_code == 403
    assert response.get_json()["error"] == "The hosted demonstration is read-only."
    assert client.get("/").headers["X-Frame-Options"] == "DENY"


def test_policy_create_list_and_report(client, csrf_headers, tmp_path):
    response = client.post("/api/policies", json={"name": "Test policy", "restricted_destinations": [str(tmp_path / "restricted")]}, headers=csrf_headers)
    assert response.status_code == 201
    assert client.get("/api/policies").get_json()["items"][0]["name"] == "Test policy"
    assert client.get("/api/reports/csv").status_code == 200
    assert client.get("/api/reports/pdf").status_code == 200


def test_csv_report_includes_alerts_and_neutralizes_formulas(client, app):
    services = app.extensions["sftms"]
    event = FileEvent("created", "/demo/source", None, "=HYPERLINK(\"https://bad\")", file_hash="abc")
    services["db"].add_event(event, "formula-event")
    services["alerts"].create(event_id=None, title="Formula-like = alert", description="Synthetic test",
                               related_file="=HYPERLINK(\"https://bad\")", source_path="/demo/source",
                               destination_path=None, severity="High", rule="test")

    response = client.get("/api/reports/csv")
    rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
    assert {row["record_type"] for row in rows} == {"event", "alert"}
    assert next(row["file_name"] for row in rows if row["record_type"] == "event").startswith("'=")
    assert next(row["severity"] for row in rows if row["record_type"] == "alert") == "High"
