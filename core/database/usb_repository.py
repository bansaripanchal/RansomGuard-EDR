import logging
import sqlite3
import time
from typing import List, Dict, Any, Optional
from core.database.database import DatabaseManager

logger = logging.getLogger("RansomGuard.USBRepository")


class USBRepository:
    """Repository for managing USB scan sessions and per-file scan results in SQLite."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def create_session(
        self,
        scan_id: str,
        drive_letter: str,
        volume_name: str = "",
        file_system: str = "",
        total_bytes: int = 0,
        free_bytes: int = 0,
        status: str = "SCANNING"
    ) -> str:
        """Inserts a new USB scan session record."""
        query = """
            INSERT OR REPLACE INTO usb_scan_sessions (
                scan_id, drive_letter, volume_name, file_system,
                total_bytes, free_bytes, start_time, status
            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        """
        try:
            self.db.execute_write(
                query,
                (scan_id, drive_letter, volume_name, file_system, total_bytes, free_bytes, status)
            )
            return scan_id
        except Exception as e:
            logger.error(f"Error creating USB scan session '{scan_id}': {e}")
            return scan_id

    def update_session(
        self,
        scan_id: str,
        status: str,
        discovered_count: int = 0,
        analyzed_count: int = 0,
        clean_count: int = 0,
        suspicious_count: int = 0,
        malicious_count: int = 0,
        unknown_count: int = 0,
        threat_count: int = 0,
        duration_sec: float = 0.0
    ):
        """Updates session completion telemetry."""
        query = """
            UPDATE usb_scan_sessions SET
                status = ?,
                end_time = CURRENT_TIMESTAMP,
                discovered_count = ?,
                analyzed_count = ?,
                clean_count = ?,
                suspicious_count = ?,
                malicious_count = ?,
                unknown_count = ?,
                threat_count = ?,
                duration_sec = ?
            WHERE scan_id = ?
        """
        try:
            self.db.execute_write(
                query,
                (
                    status, discovered_count, analyzed_count, clean_count,
                    suspicious_count, malicious_count, unknown_count, threat_count,
                    duration_sec, scan_id
                )
            )
        except Exception as e:
            logger.error(f"Error updating USB scan session '{scan_id}': {e}")

    def save_scan_results(self, scan_id: str, records: List[Dict[str, Any]]):
        """Bulk inserts file analysis records for a scan session."""
        if not records:
            return

        query = """
            INSERT INTO usb_scan_results (
                scan_id, file_path, filename, verdict, severity,
                risk_score, threat_name, reason, sha256, file_size,
                file_type, evidence, detection_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params_list = []
        for r in records:
            evidence_str = "\n".join(r.get("evidence_list", [])) if isinstance(r.get("evidence_list"), list) else str(r.get("evidence", ""))
            params_list.append((
                scan_id,
                r.get("file_path", ""),
                r.get("filename", ""),
                r.get("verdict", "UNKNOWN"),
                r.get("severity", "LOW"),
                r.get("risk_score", 0),
                r.get("threat_name", "Clean File"),
                r.get("reason", ""),
                r.get("sha256", "Not available"),
                r.get("file_size", 0),
                r.get("file_type", "Unknown"),
                evidence_str,
                r.get("detection_source", "USB Initial Scan")
            ))

        try:
            self.db.execute_write_many(query, params_list)
        except Exception as e:
            logger.error(f"Error saving USB scan results for session '{scan_id}': {e}")

    def get_recent_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves recent USB scan sessions ordered by timestamp descending."""
        query = """
            SELECT scan_id, drive_letter, volume_name, file_system,
                   total_bytes, free_bytes, start_time, end_time, status,
                   discovered_count, analyzed_count, clean_count,
                   suspicious_count, malicious_count, unknown_count,
                   threat_count, duration_sec
            FROM usb_scan_sessions
            ORDER BY start_time DESC
            LIMIT ?
        """
        try:
            rows = self.db.execute_read(query, (limit,))
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Error reading USB scan sessions: {e}")
            return []

    def get_session_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieves all file results for a specific scan session."""
        query = """
            SELECT id, scan_id, file_path, filename, verdict, severity,
                   risk_score, threat_name, reason, sha256, file_size,
                   file_type, evidence, detection_source, detection_time
            FROM usb_scan_results
            WHERE scan_id = ?
            ORDER BY id ASC
        """
        try:
            rows = self.db.execute_read(query, (scan_id,))
            records = []
            for r in rows:
                d = dict(r)
                ev_raw = d.get("evidence", "")
                d["evidence_list"] = ev_raw.split("\n") if ev_raw else []
                records.append(d)
            return records
        except Exception as e:
            logger.error(f"Error reading USB scan results for '{scan_id}': {e}")
            return []
