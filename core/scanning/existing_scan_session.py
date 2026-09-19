import os
import time
import uuid
import logging
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from core.database.database import DatabaseManager

logger = logging.getLogger("RansomGuard.ScanSession")

SCAN_MODE_INCREMENTAL = "INCREMENTAL"
SCAN_MODE_FULL = "FULL"

SCAN_STATUS_IDLE = "IDLE"
SCAN_STATUS_DISCOVERING = "DISCOVERING"
SCAN_STATUS_SCANNING = "SCANNING"
SCAN_STATUS_PAUSED = "PAUSED"
SCAN_STATUS_COMPLETED = "COMPLETED"
SCAN_STATUS_CANCELLED = "CANCELLED"
SCAN_STATUS_ERROR = "ERROR"


@dataclass
class ScanSessionStats:
    """Holds atomic telemetry for an active or completed Existing File Scan session."""
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    mode: str = SCAN_MODE_INCREMENTAL
    status: str = SCAN_STATUS_IDLE
    protected_drives: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    discovered_count: int = 0
    analyzed_count: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    unknown_count: int = 0
    threat_count: int = 0
    skipped_count: int = 0
    error_count: int = 0
    cancelled_count: int = 0
    detected_threats: List[Dict[str, Any]] = field(default_factory=list)

    current_file: str = ""

    def elapsed_seconds(self) -> float:
        """Returns elapsed scan duration."""
        if self.end_time:
            return max(0.0, self.end_time - self.start_time)
        return max(0.0, time.time() - self.start_time)

    def progress_percent(self) -> float:
        """Returns progress percentage from 0.0 to 100.0."""
        if self.status == SCAN_STATUS_COMPLETED:
            return 100.0
        if self.discovered_count <= 0:
            return 0.0
        pct = (self.analyzed_count / self.discovered_count) * 100.0
        return max(0.0, min(99.9, pct))

    def rate_files_per_sec(self) -> float:
        """Returns processing throughput rate."""
        elapsed = self.elapsed_seconds()
        if elapsed <= 0.1:
            return 0.0
        return round(self.analyzed_count / elapsed, 1)

    def estimated_remaining_seconds(self) -> Optional[float]:
        """Calculates estimated remaining time in seconds."""
        if self.status in (SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED, SCAN_STATUS_IDLE):
            return 0.0
        remaining_files = max(0, self.discovered_count - self.analyzed_count)
        rate = self.rate_files_per_sec()
        if rate > 0 and remaining_files > 0:
            return remaining_files / rate
        return None

    def formatted_time_remaining(self) -> str:
        """Formats remaining time into human readable string (e.g. '~2 min remaining')."""
        sec = self.estimated_remaining_seconds()
        if sec is None:
            return "Calculating..."
        if sec < 5:
            return "A few seconds remaining"
        if sec < 60:
            return f"~{int(sec)}s remaining"
        minutes = int(sec // 60)
        return f"~{minutes} min remaining"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes session stats for UI consumption."""
        return {
            "scan_id": self.scan_id,
            "mode": self.mode,
            "status": self.status,
            "protected_drives": list(self.protected_drives),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "elapsed_sec": round(self.elapsed_seconds(), 1),
            "discovered_count": self.discovered_count,
            "analyzed_count": self.analyzed_count,
            "clean_count": self.clean_count,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "unknown_count": self.unknown_count,
            "threat_count": self.threat_count,
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "current_file": self.current_file,
            "progress_percent": round(self.progress_percent(), 1),
            "rate_files_per_sec": self.rate_files_per_sec(),
            "time_remaining_str": self.formatted_time_remaining(),
            "detected_threats": list(self.detected_threats)
        }


class BatchPersistenceWriter:
    """
    Accumulates file scan cache entries and writes them to SQLite in bulk
    every N files or every T seconds. Prevents I/O blocking and SQLite locking.
    """

    def __init__(self, db_manager: DatabaseManager, batch_size: int = 500, flush_interval_sec: float = 2.0):
        self.db = db_manager
        self.batch_size = batch_size
        self.flush_interval = flush_interval_sec
        self.lock = threading.Lock()
        self.buffer: List[tuple] = []
        self.last_flush_time = time.time()

    def record_analyzed_file(self, record: Dict[str, Any]):
        """Queues an analyzed file record for batch insertion into existing_scan_cache."""
        row_tuple = (
            record["file_path"],
            record.get("mtime_ns", 0),
            record.get("ctime_ns", 0),
            record.get("file_size", 0),
            record.get("prefix_hash", ""),
            record.get("verdict", "UNKNOWN"),
            record.get("risk_score", 0),
            record.get("severity", "LOW"),
            record.get("threat_name", "Clean File"),
            record.get("reason", ""),
            record.get("sha256", "Not available"),
            record.get("file_type", "Unknown"),
            time.strftime("%Y-%m-%d %H:%M:%S")
        )

        should_flush = False
        with self.lock:
            self.buffer.append(row_tuple)
            now = time.time()
            if len(self.buffer) >= self.batch_size or (now - self.last_flush_time) >= self.flush_interval:
                should_flush = True

        if should_flush:
            self.flush()

    def flush(self):
        """Flushes all queued cache entries to SQLite in a single transaction."""
        to_commit: List[tuple] = []
        with self.lock:
            if not self.buffer:
                return
            to_commit = self.buffer
            self.buffer = []
            self.last_flush_time = time.time()

        if not to_commit:
            return

        query = """
            INSERT OR REPLACE INTO existing_scan_cache (
                file_path, mtime_ns, ctime_ns, file_size, prefix_hash, verdict,
                risk_score, severity, threat_name, reason, sha256, file_type, last_scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            self.db.execute_write_many(query, to_commit)
        except Exception as e:
            logger.error(f"Error executing batch write to existing_scan_cache: {e}", exc_info=True)

    def persist_session_state(self, stats: ScanSessionStats):
        """Persists the full session summary record into existing_scan_sessions."""
        drives_str = ",".join(stats.protected_drives)
        start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.start_time))
        end_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.end_time)) if stats.end_time else None
        
        summary_text = (
            f"{stats.discovered_count} discovered · {stats.analyzed_count} checked · "
            f"{stats.threat_count} threats detected"
        ) if stats.threat_count > 0 else (
            f"{stats.discovered_count} discovered · {stats.analyzed_count} checked · No threats found"
        )

        query = """
            INSERT OR REPLACE INTO existing_scan_sessions (
                scan_id, start_time, end_time, mode, status, protected_drives,
                discovered_count, analyzed_count, clean_count, suspicious_count,
                malicious_count, unknown_count, threat_count, cancelled_count,
                error_count, skipped_count, duration_sec, summary_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            stats.scan_id,
            start_str,
            end_str,
            stats.mode,
            stats.status,
            drives_str,
            stats.discovered_count,
            stats.analyzed_count,
            stats.clean_count,
            stats.suspicious_count,
            stats.malicious_count,
            stats.unknown_count,
            stats.threat_count,
            stats.cancelled_count,
            stats.error_count,
            stats.skipped_count,
            round(stats.elapsed_seconds(), 2),
            summary_text
        )
        try:
            self.db.execute_write(query, params)
        except Exception as e:
            logger.error(f"Error persisting scan session state for {stats.scan_id}: {e}", exc_info=True)

        # Persist detected threats to existing_scan_threats table
        if stats.detected_threats:
            threat_rows = []
            for t in stats.detected_threats:
                ev_str = ""
                if t.get("evidence_list"):
                    ev_str = "\n".join(t["evidence_list"])
                elif t.get("evidence"):
                    ev_str = str(t["evidence"])
                elif t.get("reason"):
                    ev_str = f"Rule: {t.get('threat_name', 'Security Threat')} | {t.get('reason')} | +{t.get('risk_score', 0)}"

                threat_rows.append((
                    stats.scan_id,
                    t["file_path"],
                    t.get("filename") or os.path.basename(t["file_path"]),
                    t.get("verdict", "SUSPICIOUS"),
                    t.get("severity", "LOW"),
                    t.get("risk_score", 0),
                    t.get("threat_name", "Security Threat"),
                    t.get("reason", "Suspicious indicator observed"),
                    t.get("detection_source", "Existing File Scan"),
                    t.get("sha256", "Not available"),
                    t.get("file_size", 0),
                    t.get("file_type", "Unknown"),
                    t.get("mtime_ns", 0),
                    t.get("ctime_ns", 0),
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    ev_str
                ))
            threat_query = """
                INSERT INTO existing_scan_threats (
                    scan_id, file_path, filename, verdict, severity,
                    risk_score, threat_name, reason, detection_source,
                    sha256, file_size, file_type, mtime_ns, ctime_ns,
                    detection_time, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            try:
                self.db.execute_write_many(threat_query, threat_rows)
            except Exception as e:
                logger.error(f"Error persisting threats for scan {stats.scan_id}: {e}", exc_info=True)
