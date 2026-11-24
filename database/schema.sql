PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS monitoring_directories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    source_directory TEXT NOT NULL DEFAULT '',
    allowed_destinations TEXT NOT NULL DEFAULT '[]',
    restricted_destinations TEXT NOT NULL DEFAULT '[]',
    extensions TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'Medium',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_path TEXT,
    destination_path TEXT,
    file_name TEXT NOT NULL,
    extension TEXT NOT NULL DEFAULT '',
    file_size INTEGER,
    file_hash TEXT,
    username TEXT NOT NULL DEFAULT 'unknown',
    process_name TEXT NOT NULL DEFAULT 'unavailable',
    classification TEXT NOT NULL DEFAULT 'Normal',
    risk_level TEXT NOT NULL DEFAULT 'Informational',
    authorization_status TEXT NOT NULL DEFAULT 'Requires Investigation',
    is_directory INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_file_events_file_name ON file_events(file_name);

CREATE TABLE IF NOT EXISTS integrity_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL UNIQUE,
    file_name TEXT NOT NULL,
    baseline_hash TEXT,
    current_hash TEXT,
    status TEXT NOT NULL DEFAULT 'Pending Verification',
    protected INTEGER NOT NULL DEFAULT 1,
    last_verified_at TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    related_event_id INTEGER,
    related_file TEXT,
    source_path TEXT,
    destination_path TEXT,
    severity TEXT NOT NULL,
    detection_rule TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    investigation_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(related_event_id) REFERENCES file_events(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC);

CREATE TABLE IF NOT EXISTS application_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
