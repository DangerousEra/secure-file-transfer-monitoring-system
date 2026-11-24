from pathlib import Path

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path: Path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "DATABASE_PATH": tmp_path / "test.db", "REPORT_DIR": tmp_path / "reports", "DEMO_DIR": tmp_path / "demo"})
    yield app
    app.extensions["sftms"]["monitor"].stop()


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client) -> dict:
    return {"X-CSRF-Token": client.get("/api/csrf-token").get_json()["token"]}


@pytest.fixture()
def csrf_headers(client):
    return csrf(client)
