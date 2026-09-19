import os
from core.database.database import DatabaseManager

class IncidentsRepository:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()

    def insert_incident(self, threat_name, severity, risk_score, affected_folder, detection_reason,
                        created_count=0, modified_count=0, renamed_count=0, deleted_count=0,
                        process_pid=None, process_name=None, recommendation="", status="ACTIVE",
                        affected_file=None, full_path=None, verdict="UNKNOWN", evidence="",
                        attribution_status="UNAVAILABLE", file_size=None, sha256=None, file_type=None,
                        dismissed=0, detection_source="Scan Center"):
        """Creates a new correlated security incident in the database."""
        query = """
            INSERT INTO incidents (
                threat_name, severity, risk_score, affected_folder, detection_reason,
                created_count, modified_count, renamed_count, deleted_count,
                process_pid, process_name, recommendation, status,
                affected_file, full_path, verdict, evidence,
                attribution_status, file_size, sha256, file_type, dismissed, detection_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        return self.db.execute_write(query, (
            threat_name, severity, risk_score, affected_folder, detection_reason,
            created_count, modified_count, renamed_count, deleted_count,
            process_pid, process_name, recommendation, status,
            affected_file, full_path, verdict, evidence,
            attribution_status, file_size, sha256, file_type, dismissed, detection_source
        ))

    def update_incident_counts(self, incident_id, created_add=0, modified_add=0, renamed_add=0, deleted_add=0,
                               risk_score=None, severity=None, detection_reason=None,
                               affected_file=None, full_path=None, verdict=None, evidence=None,
                               attribution_status=None, file_size=None, sha256=None, file_type=None,
                               process_name=None, process_pid=None, detection_source=None):
        """Updates event counters and severity/risk scores of an ongoing incident."""
        updates = []
        params = []
        
        if created_add > 0:
            updates.append("created_count = created_count + ?")
            params.append(created_add)
        if modified_add > 0:
            updates.append("modified_count = modified_count + ?")
            params.append(modified_add)
        if renamed_add > 0:
            updates.append("renamed_count = renamed_count + ?")
            params.append(renamed_add)
        if deleted_add > 0:
            updates.append("deleted_count = deleted_count + ?")
            params.append(deleted_add)
            
        if risk_score is not None:
            updates.append("risk_score = ?")
            params.append(risk_score)
        if severity is not None:
            updates.append("severity = ?")
            params.append(severity)
        if detection_reason is not None:
            updates.append("detection_reason = ?")
            params.append(detection_reason)
        if affected_file is not None:
            updates.append("affected_file = ?")
            params.append(affected_file)
        if full_path is not None:
            updates.append("full_path = ?")
            params.append(full_path)
        if verdict is not None:
            updates.append("verdict = ?")
            params.append(verdict)
        if evidence is not None:
            updates.append("evidence = ?")
            params.append(evidence)
        if attribution_status is not None:
            updates.append("attribution_status = ?")
            params.append(attribution_status)
        if file_size is not None:
            updates.append("file_size = ?")
            params.append(file_size)
        if sha256 is not None:
            updates.append("sha256 = ?")
            params.append(sha256)
        if file_type is not None:
            updates.append("file_type = ?")
            params.append(file_type)
        if process_name is not None:
            updates.append("process_name = ?")
            params.append(process_name)
        if process_pid is not None:
            updates.append("process_pid = ?")
            params.append(process_pid)
        if detection_source is not None:
            updates.append("detection_source = ?")
            params.append(detection_source)
            
        if not updates:
            return
            
        updates.append("detection_time = CURRENT_TIMESTAMP")
        
        query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
        params.append(incident_id)
        
        self.db.execute_write(query, tuple(params))

    def sync_incident_counts(self, incident_id):
        """
        Synchronizes incident created/modified/renamed/deleted counters directly from the
        actual file_events records linked to this incident in SQLite.
        """
        counts = self.get_incident_event_counts(incident_id)
        if counts and sum(counts.values()) > 0:
            query = """
                UPDATE incidents
                SET 
                    created_count = ?,
                    modified_count = ?,
                    renamed_count = ?,
                    deleted_count = ?
                WHERE id = ?
            """
            self.db.execute_write(query, (
                counts["created_count"],
                counts["modified_count"],
                counts["renamed_count"],
                counts["deleted_count"],
                incident_id
            ))

    def get_incident(self, incident_id):
        """Fetches a specific incident by ID with live event counts."""
        query = "SELECT * FROM incidents WHERE id = ?"
        row = self.db.execute_read_one(query, (incident_id,))
        if not row:
            return None
        d = dict(row)
        counts = self.get_incident_event_counts(incident_id)
        if counts and sum(counts.values()) > 0:
            d["created_count"] = counts["created_count"]
            d["modified_count"] = counts["modified_count"]
            d["renamed_count"] = counts["renamed_count"]
            d["deleted_count"] = counts["deleted_count"]
        return d

    def get_incident_event_counts(self, incident_id):
        """Retrieves exact event breakdown from file_events for this incident."""
        query = """
            SELECT 
                SUM(CASE WHEN event_type = 'CREATE' THEN 1 ELSE 0 END) as created_count,
                SUM(CASE WHEN event_type = 'MODIFY' THEN 1 ELSE 0 END) as modified_count,
                SUM(CASE WHEN event_type = 'RENAME' THEN 1 ELSE 0 END) as renamed_count,
                SUM(CASE WHEN event_type = 'DELETE' THEN 1 ELSE 0 END) as deleted_count
            FROM file_events
            WHERE incident_id = ?
        """
        row = self.db.execute_read_one(query, (incident_id,))
        if row and (row["created_count"] is not None or row["modified_count"] is not None):
            return {
                "created_count": row["created_count"] or 0,
                "modified_count": row["modified_count"] or 0,
                "renamed_count": row["renamed_count"] or 0,
                "deleted_count": row["deleted_count"] or 0
            }
        return {
            "created_count": 0,
            "modified_count": 0,
            "renamed_count": 0,
            "deleted_count": 0
        }

    def get_active_incident_by_folder(self, folder_path, age_seconds=60):
        """
        Looks for an active incident in the folder hierarchy within the last N seconds.
        Used by the correlation engine to merge related events.
        """
        if not folder_path:
            return None
        norm_folder = os.path.normpath(folder_path)
        query = """
            SELECT * FROM incidents
            WHERE (affected_folder = ? OR ? LIKE (affected_folder || '%'))
              AND status = 'ACTIVE'
              AND (strftime('%s', 'now') - strftime('%s', detection_time)) < ?
            ORDER BY detection_time DESC
            LIMIT 1
        """
        return self.db.execute_read_one(query, (norm_folder, norm_folder, age_seconds))

    def get_active_incident_by_path_or_hash(self, full_path, sha256=None):
        """
        Looks for an existing incident matching either the exact normalized full file path
        or matching SHA-256 hash. Used for duplicate incident suppression across scans.
        """
        if not full_path and not sha256:
            return None

        norm_path = os.path.normpath(full_path) if full_path else None
        if norm_path and sha256 and sha256 not in ("Not available", "N/A"):
            query = """
                SELECT * FROM incidents
                WHERE (full_path = ? OR sha256 = ?)
                ORDER BY detection_time DESC, id DESC
                LIMIT 1
            """
            return self.db.execute_read_one(query, (norm_path, sha256))
        elif norm_path:
            query = """
                SELECT * FROM incidents
                WHERE full_path = ?
                ORDER BY detection_time DESC, id DESC
                LIMIT 1
            """
            return self.db.execute_read_one(query, (norm_path,))
        elif sha256 and sha256 not in ("Not available", "N/A"):
            query = """
                SELECT * FROM incidents
                WHERE sha256 = ?
                ORDER BY detection_time DESC, id DESC
                LIMIT 1
            """
            return self.db.execute_read_one(query, (sha256,))
        return None

    def get_incidents(self, severity_filter=None, status_filter=None, limit=100, offset=0, include_dismissed=False):
        """Retrieves incidents list, filtered by severity, status, and dismissed state."""
        conditions = []
        params = []
        
        if not include_dismissed:
            conditions.append("(dismissed = 0 OR dismissed IS NULL)")

        if severity_filter:
            conditions.append("severity = ?")
            params.append(severity_filter)
        if status_filter:
            conditions.append("status = ?")
            params.append(status_filter)
            
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f"""
            SELECT * FROM incidents
            {where_clause}
            ORDER BY detection_time DESC, id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        rows = self.db.execute_read(query, tuple(params))
        result = []
        for r in rows:
            d = dict(r)
            counts = self.get_incident_event_counts(d["id"])
            if counts and sum(counts.values()) > 0:
                d["created_count"] = counts["created_count"]
                d["modified_count"] = counts["modified_count"]
                d["renamed_count"] = counts["renamed_count"]
                d["deleted_count"] = counts["deleted_count"]
            result.append(d)
        return result

    def dismiss_incident(self, incident_id):
        """
        Persistently marks an incident as dismissed from the Threat Repository in SQLite.
        Does NOT alter the incident's status (ACTIVE/RESOLVED), does not remove historical evidence,
        and does not affect any other incidents.
        """
        query = "UPDATE incidents SET dismissed = 1 WHERE id = ?"
        self.db.execute_write(query, (incident_id,))

    def undismiss_incident(self, incident_id):
        """Restores visibility of an incident in the Threat Repository."""
        query = "UPDATE incidents SET dismissed = 0 WHERE id = ?"
        self.db.execute_write(query, (incident_id,))

    def is_incident_dismissed(self, incident_id):
        """Checks if a specific incident has been dismissed in the database."""
        row = self.db.execute_read_one("SELECT dismissed FROM incidents WHERE id = ?", (incident_id,))
        if not row:
            return False
        return bool(row["dismissed"] == 1)

    def resolve_incident(self, incident_id):
        """Marks an incident as RESOLVED."""
        query = "UPDATE incidents SET status = 'RESOLVED' WHERE id = ?"
        self.db.execute_write(query, (incident_id,))

    def get_total_incidents_count(self, include_dismissed=False):
        """Returns the total number of incidents logged."""
        conditions = []
        params = []
        if not include_dismissed:
            conditions.append("(dismissed = 0 OR dismissed IS NULL)")
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT COUNT(*) as count FROM incidents {where_clause}"
        row = self.db.execute_read_one(query, tuple(params))
        return row["count"] if row else 0

    def get_active_incidents_count(self, include_dismissed=False):
        """Returns the count of currently ACTIVE incidents."""
        conditions = ["status = 'ACTIVE'"]
        if not include_dismissed:
            conditions.append("(dismissed = 0 OR dismissed IS NULL)")
        where_clause = f"WHERE {' AND '.join(conditions)}"
        query = f"SELECT COUNT(*) as count FROM incidents {where_clause}"
        row = self.db.execute_read_one(query)
        return row["count"] if row else 0

    def get_unresolved_incidents(self, include_dismissed=False):
        """Returns all unresolved active incidents."""
        conditions = ["status = 'ACTIVE'"]
        if not include_dismissed:
            conditions.append("(dismissed = 0 OR dismissed IS NULL)")
        query = f"SELECT * FROM incidents WHERE {' AND '.join(conditions)} ORDER BY risk_score DESC"
        return self.db.execute_read(query)

    def get_incidents_summary(self, include_dismissed=False):
        """Returns real summary counts: active, total, high_critical, resolved from database."""
        dismissed_filter = " AND (dismissed = 0 OR dismissed IS NULL)" if not include_dismissed else ""

        total_row = self.db.execute_read_one(f"SELECT COUNT(*) as c FROM incidents WHERE 1=1{dismissed_filter}")
        active_row = self.db.execute_read_one(f"SELECT COUNT(*) as c FROM incidents WHERE status = 'ACTIVE'{dismissed_filter}")
        resolved_row = self.db.execute_read_one(f"SELECT COUNT(*) as c FROM incidents WHERE status = 'RESOLVED'{dismissed_filter}")
        high_crit_row = self.db.execute_read_one(f"SELECT COUNT(*) as c FROM incidents WHERE severity IN ('HIGH', 'CRITICAL'){dismissed_filter}")

        return {
            "total": total_row["c"] if total_row else 0,
            "active": active_row["c"] if active_row else 0,
            "resolved": resolved_row["c"] if resolved_row else 0,
            "high_critical": high_crit_row["c"] if high_crit_row else 0
        }

