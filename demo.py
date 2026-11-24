"""Safe, repeatable demonstration using only synthetic files under data/demo_environment."""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from config import Config


DEMO_FOLDERS = ("monitored", "sensitive", "authorized", "restricted", "usb_simulation", "cloud_sync_simulation")


def setup_demo_environment(db, root: Path = Config.DEMO_DIR) -> dict:
    """Create synthetic demo folders and seed configuration. Does not touch user folders."""
    root = Path(root).resolve()
    for folder in DEMO_FOLDERS:
        (root / folder).mkdir(parents=True, exist_ok=True)
    # These contents are explicitly synthetic. They are never derived from user data.
    (root / "sensitive" / "protected_financial_record.csv").write_text("record_id,amount\nDEMO-001,100\n", encoding="utf-8")
    (root / "sensitive" / "restricted_transfer.csv").write_text("record_id,amount\nDEMO-TRANSFER,250\n", encoding="utf-8")
    (root / "sensitive" / "authorized_summary.pdf").write_bytes(b"Synthetic PDF placeholder for SFTMS demo only.")
    labels = {"monitored": "Monitored directory", "sensitive": "Sensitive documents", "authorized": "Authorized destination",
              "restricted": "Restricted destination", "usb_simulation": "USB simulation", "cloud_sync_simulation": "Cloud sync simulation"}
    for folder, label in labels.items():
        db.execute("""INSERT INTO monitoring_directories(path,label,enabled) VALUES(?,?,1)
                    ON CONFLICT(path) DO UPDATE SET label=excluded.label,enabled=1""", (str(root / folder), label))
    restricted_paths = [str(root / name) for name in ("restricted", "usb_simulation", "cloud_sync_simulation")]
    existing = db.one("SELECT id FROM security_policies WHERE name=?", ("Sensitive transfer boundary",))
    values = ("Sensitive transfer boundary", "Flags sensitive files placed in a configured restricted or simulated external destination.",
              str(root / "sensitive"), "[\"" + str(root / "authorized").replace("\\", "\\\\") + "\"]",
              __import__("json").dumps(restricted_paths), __import__("json").dumps([".csv", ".pdf", ".docx", ".xlsx", ".env", ".pem", ".key"]), "High", 1)
    if existing:
        db.execute("""UPDATE security_policies SET description=?,source_directory=?,allowed_destinations=?,restricted_destinations=?,extensions=?,severity=?,enabled=? WHERE id=?""",
                   values[1:] + (existing["id"],))
    else:
        db.execute("""INSERT INTO security_policies(name,description,source_directory,allowed_destinations,restricted_destinations,extensions,severity,enabled) VALUES(?,?,?,?,?,?,?,?)""", values)
    return {"root": str(root), "folders": {folder: str(root / folder) for folder in DEMO_FOLDERS}}


def run_demo() -> None:
    """Run the six classroom scenarios after attaching the actual Watchdog monitor."""
    from app import create_app
    app = create_app()
    services = app.extensions["sftms"]
    details = setup_demo_environment(services["db"], Path(app.config["DEMO_DIR"]))
    root = Path(details["root"])
    monitor = services["monitor"]
    monitor.restart()
    time.sleep(1)
    print(f"Demo monitor: {monitor.status()}")
    # 1. Normal creation
    (root / "monitored" / "normal_note.txt").write_text("Synthetic normal activity\n", encoding="utf-8")
    # 2. Policy violation movement. This supplies Watchdog a source and destination for evaluation.
    violation_source = root / "sensitive" / "restricted_transfer.csv"
    violation_destination = root / "restricted" / violation_source.name
    if violation_destination.exists():
        violation_destination.unlink()
    shutil.move(violation_source, violation_destination)
    # 3. Integrity mismatch
    protected = root / "sensitive" / "protected_financial_record.csv"
    services["integrity"].protect_file(protected, "Synthetic demo protected record")
    protected.write_text("record_id,amount\nDEMO-001,999\n", encoding="utf-8")
    # 4. Protected deletion
    deletion_target = root / "sensitive" / "delete_me.txt"
    deletion_target.write_text("Synthetic deletion test", encoding="utf-8")
    services["integrity"].protect_file(deletion_target, "Synthetic deletion test")
    deletion_target.unlink()
    # 5. Bulk activity
    # Create a margin for filesystem event coalescing, then wait for the alert worker.
    bulk_run_id = time.time_ns()
    usb_folder = root / "usb_simulation"
    for index in range(Config.BULK_EVENT_THRESHOLD * 6):
        (usb_folder / f"bulk_demo_{bulk_run_id}_{index}.txt").write_text("Synthetic bulk transfer item", encoding="utf-8")
        time.sleep(0.05)
    bulk_deadline = time.monotonic() + 30
    while time.monotonic() < bulk_deadline:
        bulk_alert = services["db"].one(
            "SELECT id FROM security_alerts WHERE title=? AND source_path=? AND destination_path=?",
            ("Suspicious bulk file activity", str(usb_folder), str(usb_folder)),
        )
        if bulk_alert:
            break
        time.sleep(0.1)
    else:
        print("Bulk alert was not observed before the demo wait expired.")
    # 6. Authorized sensitive movement
    approved_source = root / "sensitive" / "authorized_summary.pdf"
    shutil.copy2(approved_source, root / "authorized" / approved_source.name)
    time.sleep(3)
    services["integrity"].verify_all()
    monitor.stop()
    print("Demo complete. Open the dashboard to review actual persisted events and alerts.")


if __name__ == "__main__":
    run_demo()
