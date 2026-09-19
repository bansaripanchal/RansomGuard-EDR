import re
import logging
from core.database.database import DatabaseManager

logger = logging.getLogger("RansomGuard.HistoryRepository")

class HistoryRepository:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()
        self._ensure_deduplicated()

    def _ensure_deduplicated(self):
        """Runs one-time consolidation on legacy duplicate history entries if needed."""
        try:
            legacy_threats = self.db.execute_read_one(
                "SELECT id FROM history_log WHERE event_type = 'SCAN_THREAT_DETECTED' LIMIT 1"
            )
            if legacy_threats:
                self.consolidate_existing_duplicates()
        except Exception as e:
            logger.debug(f"History dedup check bypassed: {e}")

    def insert_log(self, event_type, severity, description, target=None, action_taken=None, scan_id=None):
        """
        Inserts an audit trail log entry into the history table with deduplication protection.
        Prevents redundant entries belonging to the same scan session or consecutive toggles.
        """
        try:
            # 1. Deduplication for consecutive protection toggles
            if event_type in ("PROTECTION_START", "PROTECTION_STOP"):
                last_prot = self.db.execute_read_one(
                    """
                    SELECT id, event_type FROM history_log 
                    WHERE event_type IN ('PROTECTION_START', 'PROTECTION_STOP')
                    ORDER BY id DESC LIMIT 1
                    """
                )
                if last_prot and last_prot["event_type"] == event_type:
                    logger.debug(f"Suppressed consecutive {event_type} duplicate entry.")
                    return last_prot["id"]

            # 2. Deduplication & consolidation for Security Scan sessions
            if event_type in ("SECURITY_SCAN", "SCAN_COMPLETED", "EXISTING_SCAN_COMPLETED"):
                if target:
                    recent_scan = self.db.execute_read_one(
                        """
                        SELECT id FROM history_log 
                        WHERE event_type IN ('SECURITY_SCAN', 'SCAN_COMPLETED', 'EXISTING_SCAN_COMPLETED')
                          AND target = ?
                          AND timestamp >= datetime('now', '-45 seconds')
                        ORDER BY id DESC LIMIT 1
                        """,
                        (target,)
                    )
                    if recent_scan:
                        self.db.execute_write(
                            """
                            UPDATE history_log 
                            SET event_type = ?, severity = ?, description = ?, action_taken = ?
                            WHERE id = ?
                            """,
                            (event_type, severity, description, action_taken, recent_scan["id"])
                        )
                        logger.debug(f"Updated existing scan session record {recent_scan['id']}.")
                        return recent_scan["id"]

            # 3. Suppress rapid identical records within 15 seconds
            identical = self.db.execute_read_one(
                """
                SELECT id FROM history_log 
                WHERE event_type = ? 
                  AND (target = ? OR (target IS NULL AND ? IS NULL))
                  AND description = ?
                  AND timestamp >= datetime('now', '-15 seconds')
                ORDER BY id DESC LIMIT 1
                """,
                (event_type, target, target, description)
            )
            if identical:
                logger.debug(f"Suppressed rapid duplicate history log for event: {event_type}")
                return identical["id"]

        except Exception as e:
            logger.error(f"Error during history deduplication check: {e}")

        # Normal insertion
        query = """
            INSERT INTO history_log (event_type, severity, description, target, action_taken)
            VALUES (?, ?, ?, ?, ?)
        """
        return self.db.execute_write(query, (event_type, severity, description, target, action_taken))

    def consolidate_existing_duplicates(self):
        """
        Consolidates legacy duplicate scan records into unified session entries
        and cleans up consecutive redundant protection toggles without losing real data.
        """
        try:
            # A. Update existing SCAN_COMPLETED to SECURITY_SCAN with standardized concise description
            scan_completed_rows = self.db.execute_read(
                "SELECT id, timestamp, event_type, severity, description, target, action_taken FROM history_log WHERE event_type='SCAN_COMPLETED'"
            )
            for sc in scan_completed_rows:
                sc_id = sc["id"]
                desc = sc["description"] or ""
                target = sc["target"] or ""
                ts = sc["timestamp"]

                m = re.search(r"Scanned\s+(\d+)\s+files\s*\(Clean:\s*(\d+),\s*Suspicious:\s*(\d+),\s*Malicious:\s*(\d+)", desc)
                if m:
                    scanned, clean, suspicious, malicious = m.groups()
                    new_desc = f"[Scan Center] Scan completed \u2014 {scanned} files scanned, {suspicious} suspicious, {malicious} malicious."
                else:
                    new_desc = desc

                self.db.execute_write(
                    "UPDATE history_log SET event_type='SECURITY_SCAN', description=? WHERE id=?",
                    (new_desc, sc_id)
                )

                # Delete per-file SCAN_THREAT_DETECTED rows for this scan session
                if target:
                    self.db.execute_write(
                        """
                        DELETE FROM history_log
                        WHERE event_type='SCAN_THREAT_DETECTED'
                          AND target LIKE ?
                          AND ABS(strftime('%s', timestamp) - strftime('%s', ?)) <= 120
                        """,
                        (f"{target}%", ts)
                    )

            # B. Consolidate any remaining orphaned SCAN_THREAT_DETECTED (e.g. single file scan)
            orphaned = self.db.execute_read(
                "SELECT id, target, severity FROM history_log WHERE event_type='SCAN_THREAT_DETECTED'"
            )
            for r in orphaned:
                self.db.execute_write(
                    """
                    UPDATE history_log
                    SET event_type='SECURITY_SCAN',
                        description='[Scan Center] Scan completed \u2014 1 files scanned, 1 suspicious, 0 malicious.'
                    WHERE id=?
                    """,
                    (r["id"],)
                )

            # C. Clean up consecutive duplicate protection entries
            prot_rows = self.db.execute_read(
                "SELECT id, timestamp, event_type FROM history_log WHERE event_type LIKE 'PROTECTION%' ORDER BY id ASC"
            )
            prev_type = None
            dup_prot_ids = []
            for p in prot_rows:
                if p["event_type"] == prev_type:
                    dup_prot_ids.append(p["id"])
                else:
                    prev_type = p["event_type"]

            if dup_prot_ids:
                placeholders = ",".join("?" * len(dup_prot_ids))
                self.db.execute_write(f"DELETE FROM history_log WHERE id IN ({placeholders})", tuple(dup_prot_ids))

            logger.info("History repository consolidation complete.")
        except Exception as e:
            logger.error(f"Failed to consolidate existing duplicate history: {e}", exc_info=True)

    def get_logs(self, limit=100, offset=0):
        """Retrieves history logs sorted by newest first, support paging."""
        query = """
            SELECT id, timestamp, event_type, severity, description, target, action_taken
            FROM history_log
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
        """
        return self.db.execute_read(query, (limit, offset))

    def get_total_logs_count(self):
        """Returns the total number of history records."""
        row = self.db.execute_read_one("SELECT COUNT(*) as count FROM history_log")
        return row["count"] if row else 0

    def clear_history(self):
        """Deletes all history records from the audit trail."""
        self.db.execute_write("DELETE FROM history_log")

