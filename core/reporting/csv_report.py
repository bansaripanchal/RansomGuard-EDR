import csv
import logging
from PySide6.QtCore import QThread, Signal
from core.database.database import DatabaseManager

logger = logging.getLogger("RansomGuard.CSVReport")

class CSVReportGenerator(QThread):
    finished = Signal(str) # Path to the generated CSV
    error = Signal(str)

    def __init__(self, output_path, report_type="incidents", db_manager=None):
        """
        report_type can be 'incidents', 'events', or 'history'
        """
        super(CSVReportGenerator, self).__init__()
        self.output_path = output_path
        self.report_type = report_type.lower()
        self.db = db_manager or DatabaseManager()

    def run(self):
        try:
            logger.info(f"Generating CSV export ({self.report_type}) to: {self.output_path}")
            
            if self.report_type == "incidents":
                self._export_incidents()
            elif self.report_type == "events":
                self._export_events()
            elif self.report_type == "history":
                self._export_history()
            else:
                self.error.emit(f"Unknown report type: {self.report_type}")
                return
                
            self.finished.emit(self.output_path)
            logger.info(f"CSV export finished: {self.output_path}")
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}", exc_info=True)
            self.error.emit(str(e))

    def _export_incidents(self):
        scope_clause, scope_params = self.db.get_active_scope_clause("affected_folder")
        where_clause = f"WHERE {scope_clause}"
            
        query = f"""
            SELECT id, threat_name, severity, risk_score, detection_time, status, 
                   affected_folder, affected_file, full_path, detection_reason, created_count, modified_count, 
                   renamed_count, deleted_count, process_pid, process_name, recommendation, verdict, evidence
            FROM incidents
            {where_clause}
            ORDER BY detection_time DESC
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        headers = [
            "Incident ID", "Verdict", "Threat Name", "Severity", "Risk Score", "Detection Time (UTC)", "Status",
            "Affected Folder", "Affected File", "Full Path", "Detection Reason", "Created Count", "Modified Count",
            "Renamed Count", "Deleted Count", "Process", "Evidence", "Recommendation"
        ]
        
        with open(self.output_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                pname = r["process_name"]
                p_display = pname if (pname and pname not in ("Unknown", "Unknown Process")) else "Unknown"
                evidence_clean = (r["evidence"] or "").replace("\n", " | ")
                
                writer.writerow([
                    r["id"], r["verdict"] or "UNKNOWN", r["threat_name"], r["severity"], r["risk_score"], r["detection_time"], r["status"],
                    r["affected_folder"], r["affected_file"] or "", r["full_path"] or "",
                    r["detection_reason"], r["created_count"], r["modified_count"],
                    r["renamed_count"], r["deleted_count"], p_display, evidence_clean, r["recommendation"]
                ])

    def _export_events(self):
        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
        where_clause = f"WHERE {scope_clause}"
            
        query = f"""
            SELECT id, timestamp, event_type, src_path, dest_path, extension, file_size, incident_id
            FROM file_events
            {where_clause}
            ORDER BY timestamp DESC
        """
        rows = self.db.execute_read(query, tuple(scope_params))
        headers = [
            "Event ID", "Timestamp (UTC)", "Event Type", "Source Path", "Destination Path", 
            "Extension", "File Size (Bytes)", "Incident ID Mapping"
        ]
        
        with open(self.output_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow([
                    r["id"], r["timestamp"], r["event_type"], r["src_path"], r["dest_path"] or "",
                    r["extension"], r["file_size"], r["incident_id"] or ""
                ])

    def _export_history(self):
        query = """
            SELECT id, timestamp, event_type, severity, description, target, action_taken
            FROM history_log
            ORDER BY timestamp DESC
        """
        rows = self.db.execute_read(query)
        headers = [
            "Log ID", "Timestamp (UTC)", "Event Type", "Severity", "Description", "Target Path", "Action Taken"
        ]
        
        with open(self.output_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow([
                    r["id"], r["timestamp"], r["event_type"], r["severity"], r["description"],
                    r["target"] or "", r["action_taken"] or ""
                ])
