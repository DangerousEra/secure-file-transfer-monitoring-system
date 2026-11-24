from database.models import FileEvent


def test_event_persistence_and_deduplication(app):
    db = app.extensions["sftms"]["db"]
    event = FileEvent("created", "C:/demo/a.txt", None, "a.txt")
    assert db.add_event(event, "same-key")
    assert db.add_event(event, "same-key") is None
    assert db.one("SELECT COUNT(*) AS count FROM file_events")["count"] == 1


def test_alert_status_update(app):
    alerts = app.extensions["sftms"]["alerts"]
    alert_id = alerts.create(event_id=None, title="Test", description="Test alert", related_file="test.txt", source_path=None, destination_path=None, severity="High", rule="test")
    assert alerts.update_status(alert_id, "Investigating", "Reviewed by test")
    assert app.extensions["sftms"]["db"].one("SELECT status FROM security_alerts WHERE id=?", (alert_id,))["status"] == "Investigating"
