# Database Schema Definitions for RansomGuard

SCHEMA_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS monitored_paths (
        path TEXT PRIMARY KEY,
        recursive INTEGER DEFAULT 1
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        detection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'ACTIVE',
        affected_folder TEXT,
        affected_file TEXT,
        full_path TEXT,
        detection_reason TEXT,
        created_count INTEGER DEFAULT 0,
        modified_count INTEGER DEFAULT 0,
        renamed_count INTEGER DEFAULT 0,
        deleted_count INTEGER DEFAULT 0,
        process_pid INTEGER,
        process_name TEXT,
        attribution_status TEXT DEFAULT 'UNAVAILABLE',
        recommendation TEXT,
        verdict TEXT DEFAULT 'UNKNOWN',
        evidence TEXT,
        file_size INTEGER,
        sha256 TEXT,
        file_type TEXT,
        dismissed INTEGER DEFAULT 0,
        detection_source TEXT DEFAULT 'Scan Center'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        src_path TEXT NOT NULL,
        dest_path TEXT,
        extension TEXT,
        file_size INTEGER DEFAULT 0,
        incident_id INTEGER,
        sha256 TEXT,
        process_name TEXT,
        process_pid INTEGER,
        attribution_status TEXT DEFAULT 'UNAVAILABLE',
        FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS history_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        target TEXT,
        action_taken TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS existing_scan_cache (
        file_path TEXT PRIMARY KEY,
        mtime_ns INTEGER,
        ctime_ns INTEGER,
        file_size INTEGER,
        prefix_hash TEXT,
        verdict TEXT,
        risk_score INTEGER,
        severity TEXT,
        threat_name TEXT,
        reason TEXT,
        sha256 TEXT,
        file_type TEXT,
        last_scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS existing_scan_sessions (
        scan_id TEXT PRIMARY KEY,
        start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        end_time DATETIME,
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        protected_drives TEXT,
        discovered_count INTEGER DEFAULT 0,
        analyzed_count INTEGER DEFAULT 0,
        clean_count INTEGER DEFAULT 0,
        suspicious_count INTEGER DEFAULT 0,
        malicious_count INTEGER DEFAULT 0,
        unknown_count INTEGER DEFAULT 0,
        threat_count INTEGER DEFAULT 0,
        cancelled_count INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0,
        skipped_count INTEGER DEFAULT 0,
        duration_sec REAL DEFAULT 0.0,
        summary_text TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS existing_scan_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        filename TEXT,
        verdict TEXT NOT NULL,
        severity TEXT,
        risk_score INTEGER,
        threat_name TEXT,
        reason TEXT,
        detection_source TEXT DEFAULT 'Existing File Scan',
        sha256 TEXT,
        file_size INTEGER,
        file_type TEXT,
        mtime_ns INTEGER,
        ctime_ns INTEGER,
        detection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        evidence TEXT,
        FOREIGN KEY(scan_id) REFERENCES existing_scan_sessions(scan_id) ON DELETE CASCADE
    );
    """
]

SCHEMA_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_file_events_incident_id ON file_events(incident_id);",
    "CREATE INDEX IF NOT EXISTS idx_file_events_src_path ON file_events(src_path);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(detection_time);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_affected_folder ON incidents(affected_folder);",
    "CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history_log(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_existing_scan_cache_path ON existing_scan_cache(file_path);",
    "CREATE INDEX IF NOT EXISTS idx_existing_scan_sessions_time ON existing_scan_sessions(start_time);",
    "CREATE INDEX IF NOT EXISTS idx_existing_scan_sessions_status ON existing_scan_sessions(status);",
    "CREATE INDEX IF NOT EXISTS idx_existing_scan_threats_scan_id ON existing_scan_threats(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_dismissed ON incidents(dismissed);"
]
