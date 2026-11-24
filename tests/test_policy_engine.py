import json

from core.classifier import FileClassifier
from core.event_handler import SecurityEventHandler
from core.policy_engine import PolicyEngine
from database.models import FileEvent


def test_unauthorized_movement_violates_policy(app, tmp_path):
    sensitive, restricted = tmp_path / "sensitive", tmp_path / "restricted"
    sensitive.mkdir(); restricted.mkdir()
    db = app.extensions["sftms"]["db"]
    db.execute("INSERT INTO monitoring_directories(path,label,enabled) VALUES(?,?,1)", (str(sensitive), "Sensitive documents"))
    db.execute("""INSERT INTO security_policies(name,source_directory,restricted_destinations,extensions,severity)
                  VALUES(?,?,?,?,?)""", ("block external", str(sensitive), json.dumps([str(restricted)]), json.dumps([".csv"]), "High"))
    event = FileEvent("moved", str(sensitive / "records.csv"), str(restricted / "records.csv"), "records.csv", ".csv")
    result = PolicyEngine(db, FileClassifier(db)).evaluate(event)
    assert result["authorization_status"] == "Policy Violation"
    assert result["risk_level"] == "High"


def test_authorized_movement_does_not_violate_policy(app, tmp_path):
    source, allowed, restricted = tmp_path / "source", tmp_path / "allowed", tmp_path / "restricted"
    for path in (source, allowed, restricted): path.mkdir()
    db = app.extensions["sftms"]["db"]
    db.execute("INSERT INTO monitoring_directories(path,label,enabled) VALUES(?,?,1)", (str(source), "Sensitive source"))
    db.execute("""INSERT INTO security_policies(name,source_directory,allowed_destinations,restricted_destinations,extensions,severity)
                  VALUES(?,?,?,?,?,?)""", ("allow internal", str(source), json.dumps([str(allowed)]), json.dumps([str(restricted)]), json.dumps([".csv"]), "High"))
    event = FileEvent("moved", str(source / "records.csv"), str(allowed / "records.csv"), "records.csv", ".csv")
    assert PolicyEngine(db, FileClassifier(db)).evaluate(event)["authorization_status"] == "Authorized"


def test_destination_match_requires_a_directory_boundary(tmp_path):
    root = tmp_path / "allowed"
    sibling = tmp_path / "allowed-elsewhere"
    child = root / "nested" / "record.csv"
    assert PolicyEngine._matches(str(child), str(root))
    assert not PolicyEngine._matches(str(sibling / "record.csv"), str(root))


def test_bulk_creation_events_trigger_an_alert(app, tmp_path):
    services = app.extensions["sftms"]
    root = tmp_path / "usb"
    root.mkdir()
    handler = SecurityEventHandler(services["db"], services["classifier"], services["policy_engine"],
                                   services["integrity"], services["alerts"], bulk_threshold=2, bulk_window=60)
    for index in range(3):
        path = root / f"copy-{index}.txt"
        event = FileEvent("created", str(path), None, path.name)
        event_id = services["db"].add_event(event, f"bulk-{index}")
        handler._check_bulk(event_id, event)

    assert services["db"].one("SELECT COUNT(*) AS count FROM security_alerts WHERE title='Suspicious bulk file activity'")["count"] == 1
