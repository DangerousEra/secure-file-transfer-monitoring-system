"""Secure File Transfer Monitoring System entry point."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask

from api.routes import bp
from config import Config
from core.alert_manager import AlertManager
from core.classifier import FileClassifier
from core.integrity import IntegrityService
from core.monitor import MonitoringService
from core.policy_engine import PolicyEngine
from database.db import Database


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(app.config.get("CLOUD_DEMO")),
    )
    app.config["DATABASE_PATH"] = str(app.config["DATABASE_PATH"])
    app.config["REPORT_DIR"] = str(app.config["REPORT_DIR"])
    app.config["DEMO_DIR"] = str(app.config["DEMO_DIR"])
    _configure_logging(app)
    db = Database(app.config["DATABASE_PATH"])
    db.initialize(Path(app.root_path) / "database" / "schema.sql")
    classifier = FileClassifier(db)
    integrity = IntegrityService(db)
    alerts = AlertManager(db)
    policy_engine = PolicyEngine(db, classifier)
    monitor = MonitoringService(db, classifier, policy_engine, integrity, alerts)
    app.extensions["sftms"] = {"db": db, "classifier": classifier, "integrity": integrity, "alerts": alerts,
                               "policy_engine": policy_engine, "monitor": monitor}
    app.register_blueprint(bp)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    return app


def _configure_logging(app: Flask) -> None:
    log_dir = app.config["LOG_DIR"]
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "sftms.log", maxBytes=1_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)


# Production WSGI servers, including Gunicorn, import this module-level object.
app = create_app()


if __name__ == "__main__":
    print(f"SFTMS is available at http://{app.config['HOST']}:{app.config['PORT']}")
    print("Monitoring starts only after monitored directories are configured and Start is selected.")
    app.run(host=app.config["HOST"], port=app.config["PORT"], debug=app.config["DEBUG"])
