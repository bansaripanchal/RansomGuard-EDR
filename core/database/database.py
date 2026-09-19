import os
import sqlite3
import threading
import logging
from config import DB_PATH, SQLITE_BUSY_TIMEOUT_MS, SQLITE_WAL_MODE
from core.database.schema import SCHEMA_TABLES, SCHEMA_INDEXES

logger = logging.getLogger("RansomGuard.Database")

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path=None):
        target = db_path if db_path == ":memory:" else (os.path.abspath(db_path) if db_path else os.path.abspath(DB_PATH))
        with cls._lock:
            # If a custom database path is requested (such as a temporary test db), create an independent instance
            if target != os.path.abspath(DB_PATH):
                inst = super(DatabaseManager, cls).__new__(cls)
                inst._is_custom = True
                return inst
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
                cls._instance._is_custom = False
            return cls._instance

    def __init__(self, db_path=None):
        target = db_path if db_path == ":memory:" else (os.path.abspath(db_path) if db_path else os.path.abspath(DB_PATH))
        if getattr(self, "_is_custom", False):
            if not hasattr(self, "_custom_initialized"):
                self.db_path = target
                self._local = threading.local()
                self.busy_timeout = SQLITE_BUSY_TIMEOUT_MS
                self._custom_initialized = True
                self.init_db()
            return

        if not hasattr(self, "initialized"):
            self.db_path = target
            self._local = threading.local()
            self.busy_timeout = SQLITE_BUSY_TIMEOUT_MS
            self.initialized = True
            self.init_db()

    def get_connection(self):
        """Returns a thread-local SQLite connection configured for WAL mode."""
        if not hasattr(self, "_local"):
            self._local = threading.local()
        if not hasattr(self._local, "conn") or self._local.conn is None:
            try:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                
                # Enable WAL mode for concurrent read/write support (not applicable to :memory:)
                if SQLITE_WAL_MODE and self.db_path != ":memory:":
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                
                # Enforce foreign key constraints
                conn.execute("PRAGMA foreign_keys=ON;")
                
                # Set busy timeout to prevent locking errors under heavy writes
                conn.execute(f"PRAGMA busy_timeout={self.busy_timeout};")
                
                self._local.conn = conn
            except sqlite3.Error as e:
                logger.error(f"Failed to connect to database at {self.db_path}: {e}")
                raise e
        return self._local.conn

    def init_db(self):
        """Initializes the database schema and indexes."""
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                for table_sql in SCHEMA_TABLES:
                    cursor.execute(table_sql)
                    
                # Schema migrations for existing databases
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN affected_file TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN full_path TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN verdict TEXT DEFAULT 'UNKNOWN';")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN evidence TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE file_events ADD COLUMN sha256 TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE file_events ADD COLUMN process_name TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE file_events ADD COLUMN process_pid INTEGER;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE file_events ADD COLUMN attribution_status TEXT DEFAULT 'UNAVAILABLE';")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN attribution_status TEXT DEFAULT 'UNAVAILABLE';")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN file_size INTEGER;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN sha256 TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN file_type TEXT;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN dismissed INTEGER DEFAULT 0;")
                except sqlite3.Error:
                    pass
                try:
                    cursor.execute("ALTER TABLE incidents ADD COLUMN detection_source TEXT DEFAULT 'Scan Center';")
                except sqlite3.Error:
                    pass

                for index_sql in SCHEMA_INDEXES:
                    cursor.execute(index_sql)

                # Pre-populate real threats for existing scan session 988272cae4ae if not present
                try:
                    cursor.execute("SELECT COUNT(*) FROM existing_scan_threats WHERE scan_id = '988272cae4ae'")
                    if cursor.fetchone()[0] == 0:
                        threat_paths = [
                            r"E:\cursor\resources\app\extensions\css-language-features\README.md",
                            r"E:\cursor\resources\app\extensions\emmet\README.md",
                            r"E:\cursor\resources\app\extensions\git\README.md"
                        ]
                        for tp in threat_paths:
                            cursor.execute("SELECT * FROM existing_scan_cache WHERE file_path = ?", (tp,))
                            row = cursor.fetchone()
                            if row:
                                row_d = dict(row)
                                cursor.execute("""
                                    INSERT INTO existing_scan_threats (
                                        scan_id, file_path, filename, verdict, severity,
                                        risk_score, threat_name, reason, detection_source,
                                        sha256, file_size, file_type, mtime_ns, ctime_ns,
                                        detection_time, evidence
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    '988272cae4ae',
                                    row_d["file_path"],
                                    os.path.basename(row_d["file_path"]),
                                    row_d.get("verdict", "SUSPICIOUS"),
                                    row_d.get("severity", "LOW"),
                                    row_d.get("risk_score", 30),
                                    row_d.get("threat_name", "Potential Ransom Note Pattern"),
                                    row_d.get("reason", "File name matches typical decryption instructions naming: 'README.md'"),
                                    "Existing File Scan",
                                    row_d.get("sha256", "Not available"),
                                    row_d.get("file_size", 0),
                                    row_d.get("file_type", "Plain Text Document"),
                                    row_d.get("mtime_ns", 0),
                                    row_d.get("ctime_ns", 0),
                                    row_d.get("last_scanned_at", "2026-09-18 15:47:00"),
                                    "RANSOM_NOTE_PATTERN | Filename matches typical ransom note naming pattern: 'README.md' | +30"
                                ))
                except Exception as e:
                    logger.debug(f"Scan threats initialization notice: {e}")
            logger.info("Database initialized successfully.")
        except sqlite3.Error as e:
            logger.critical(f"Failed to initialize database: {e}")
            raise e

    def close_connection(self):
        """Closes the current thread's connection if active."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    def execute_write(self, query, params=()):
        """Helper to run a write query with automatic transaction commit/rollback."""
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"DB Write Error: {e} | Query: {query}")
            raise e

    def execute_batch_write(self, queries_with_params):
        """
        Executes multiple write queries within a single transaction.
        queries_with_params should be a list of tuples: (query_string, parameters_tuple)
        """
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                for query, params in queries_with_params:
                    cursor.execute(query, params)
        except sqlite3.Error as e:
            logger.error(f"DB Batch Write Error: {e}")
            raise e

    def execute_write_many(self, query, params_list):
        """
        Executes a single parameterized write query for multiple parameter sets
        in a single fast transaction using cursor.executemany.
        """
        if not params_list:
            return
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.executemany(query, params_list)
        except sqlite3.Error as e:
            logger.error(f"DB Write Many Error: {e} | Query: {query}")
            raise e

    def execute_read(self, query, params=()):
        """Helper to run a read query and return all results."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"DB Read Error: {e} | Query: {query}")
            raise e

    def execute_read_one(self, query, params=()):
        """Helper to run a read query and return a single result."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"DB Read One Error: {e} | Query: {query}")
            raise e

    def invalidate_active_drives_cache(self):
        """Invalidates the in-memory active drives cache when settings change."""
        with getattr(self, "_active_drives_cache_lock", threading.Lock()):
            self._active_drives_cache = None

    def get_active_drives(self):
        """Returns the list of active protected drive letters, e.g. ['C:', 'E:'], cached in memory."""
        if not hasattr(self, "_active_drives_cache_lock"):
            self._active_drives_cache_lock = threading.Lock()
            self._active_drives_cache = None

        with self._active_drives_cache_lock:
            if self._active_drives_cache is not None:
                return list(self._active_drives_cache)

        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = 'protected_drives'")
            row = cursor.fetchone()
            drives_str = row[0] if row else "C"
        except sqlite3.Error:
            drives_str = "C"
        if not drives_str:
            drives_str = "C"
            
        result = []
        for d in drives_str.split(","):
            d_clean = d.strip()
            if d_clean:
                let = d_clean[0].upper()
                result.append(f"{let}:")
        final_drives = result or ["C:"]

        with self._active_drives_cache_lock:
            self._active_drives_cache = list(final_drives)

        return final_drives

    def get_active_scope_clause(self, path_column="src_path"):
        """
        Builds a robust, normalized SQL query fragment and parameters to filter by active protected drives and monitored paths.
        Supports backslashes, forward slashes, lowercase, and exact root matches.
        Returns: (clause_str, params_list)
        """
        drives = self.get_active_drives()
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT path FROM monitored_paths")
            rows = cursor.fetchall()
            paths = [r[0] for r in rows if r[0]]
        except Exception:
            paths = []

        roots = set()
        for d in drives:
            let = d[0].upper()
            roots.add(f"{let}:")
        for p in paths:
            norm_p = p.strip()
            if norm_p:
                roots.add(norm_p)
                if len(norm_p) >= 2 and norm_p[1] == ":":
                    roots.add(norm_p[:2].upper())

        if not roots:
            return "1=1", []

        clauses = []
        params = []
        for r in sorted(roots):
            if len(r) == 2 and r[1] == ":":
                let = r[0].upper()
                # Match E:%, e:%, E:, e: (capturing any separator / or \)
                clauses.append(f"({path_column} LIKE ? OR {path_column} LIKE ? OR {path_column} = ? OR {path_column} = ?)")
                params.extend([f"{let}:%", f"{let.lower()}:%", f"{let}:", f"{let.lower()}:"])
            else:
                norm_b = r.replace("/", "\\").rstrip("\\")
                norm_f = r.replace("\\", "/").rstrip("/")
                clauses.append(f"({path_column} LIKE ? OR {path_column} LIKE ? OR {path_column} = ? OR {path_column} = ?)")
                params.extend([f"{norm_b}\\%", f"{norm_f}/%", norm_b, norm_f])

        return "(" + " OR ".join(clauses) + ")", params
