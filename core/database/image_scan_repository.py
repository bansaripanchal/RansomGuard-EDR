import sqlite3
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("RansomGuard.ImageScanRepository")

class ImageScanRepository:
    def __init__(self, db_manager):
        self.db = db_manager

    def insert_scan_result(self, record: Dict[str, Any]) -> int:
        """Inserts an image hidden text scan record into SQLite database."""
        conn = self.db.get_connection()
        query = """
        INSERT INTO image_hidden_text_scans (
            scan_id, file_path, filename, sha256, file_size, file_format,
            dimensions, status, category, visible_text, hidden_text,
            detection_method, metadata_json, channel_findings,
            embedded_data_indicators, security_interpretation, duration_sec
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        );
        """
        params = (
            record.get("scan_id", ""),
            record.get("file_path", ""),
            record.get("filename", ""),
            record.get("sha256", ""),
            record.get("file_size", 0),
            record.get("file_format", ""),
            record.get("dimensions", ""),
            record.get("status", "COMPLETED"),
            record.get("category", "UNABLE TO DETERMINE"),
            record.get("visible_text", "No visible text detected."),
            record.get("hidden_text", "No hidden text detected."),
            record.get("detection_method", "Standard Analysis"),
            json.dumps(record.get("metadata", {})) if isinstance(record.get("metadata"), dict) else str(record.get("metadata", "")),
            json.dumps(record.get("channel_findings", [])) if isinstance(record.get("channel_findings"), (list, dict)) else str(record.get("channel_findings", "")),
            json.dumps(record.get("embedded_data_indicators", [])) if isinstance(record.get("embedded_data_indicators"), (list, dict)) else str(record.get("embedded_data_indicators", "")),
            record.get("security_interpretation", ""),
            record.get("duration_sec", 0.0)
        )
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting image scan result: {e}")
            return -1

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves past image hidden text scan records."""
        conn = self.db.get_connection()
        query = """
        SELECT id, scan_id, file_path, filename, sha256, file_size, file_format,
               dimensions, scan_time, status, category, visible_text, hidden_text,
               detection_method, metadata_json, channel_findings,
               embedded_data_indicators, security_interpretation, duration_sec
        FROM image_hidden_text_scans
        ORDER BY id DESC
        LIMIT ?;
        """
        results = []
        try:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            for r in rows:
                results.append(dict(r))
        except sqlite3.Error as e:
            logger.error(f"Error reading image scan history: {e}")
        return results

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific image scan record by its scan_id."""
        conn = self.db.get_connection()
        query = """
        SELECT * FROM image_hidden_text_scans WHERE scan_id = ? LIMIT 1;
        """
        try:
            cursor = conn.cursor()
            cursor.execute(query, (scan_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        except sqlite3.Error as e:
            logger.error(f"Error fetching image scan by id {scan_id}: {e}")
        return None
