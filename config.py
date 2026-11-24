"""Application configuration for the Secure File Transfer Monitoring System."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.environ.get("SFTMS_SECRET_KEY") or secrets.token_hex(32)
    DATABASE_PATH = Path(os.environ.get("SFTMS_DATABASE", BASE_DIR / "data" / "sftms.db"))
    LOG_DIR = BASE_DIR / "logs"
    REPORT_DIR = BASE_DIR / "reports"
    DEMO_DIR = Path(os.environ.get("SFTMS_DEMO_DIR", BASE_DIR / "data" / "demo_environment"))
    MAX_CONTENT_LENGTH = 64 * 1024
    BULK_EVENT_WINDOW_SECONDS = int(os.environ.get("SFTMS_BULK_WINDOW", "60"))
    BULK_EVENT_THRESHOLD = int(os.environ.get("SFTMS_BULK_THRESHOLD", "8"))
    HASH_CHUNK_SIZE = 1024 * 1024
    HOST = "127.0.0.1"
    PORT = int(os.environ.get("PORT", "5000"))
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    CLOUD_DEMO = os.environ.get("SFTMS_CLOUD_DEMO", "false").lower() == "true"
