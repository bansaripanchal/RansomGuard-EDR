from core.database.database import DatabaseManager

class EventsRepository:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()

    def insert_event(self, event_type, src_path, dest_path=None, extension="", file_size=0, incident_id=None,
                     sha256=None, process_name="Unknown", process_pid=None, attribution_status="UNAVAILABLE"):
        """Inserts a single filesystem event with process attribution and hash."""
        query = """
            INSERT INTO file_events (
                event_type, src_path, dest_path, extension, file_size, incident_id,
                sha256, process_name, process_pid, attribution_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        return self.db.execute_write(query, (
            event_type, src_path, dest_path, extension, file_size, incident_id,
            sha256, process_name, process_pid, attribution_status
        ))

    def insert_events_batch(self, events):
        """
        Inserts a list of events inside a single transaction.
        Supports both legacy 6-tuples and full 10-tuples / dicts.
        """
        query = """
            INSERT INTO file_events (
                event_type, src_path, dest_path, extension, file_size, incident_id,
                sha256, process_name, process_pid, attribution_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        normalized_events = []
        for ev in events:
            if isinstance(ev, dict):
                normalized_events.append((
                    query, (
                        ev.get("event_type"), ev.get("src_path"), ev.get("dest_path"),
                        ev.get("extension", ""), ev.get("file_size", 0), ev.get("incident_id"),
                        ev.get("sha256"), ev.get("process_name", "Unknown"),
                        ev.get("process_pid"), ev.get("attribution_status", "UNAVAILABLE")
                    )
                ))
            elif len(ev) == 6:
                # Legacy 6-tuple
                normalized_events.append((
                    query, (
                        ev[0], ev[1], ev[2], ev[3], ev[4], ev[5],
                        None, "Unknown", None, "UNAVAILABLE"
                    )
                ))
            elif len(ev) == 7:
                # 7-tuple with sha256
                normalized_events.append((
                    query, (
                        ev[0], ev[1], ev[2], ev[3], ev[4], ev[5],
                        ev[6], "Unknown", None, "UNAVAILABLE"
                    )
                ))
            elif len(ev) >= 10:
                normalized_events.append((query, tuple(ev[:10])))
            else:
                padded = list(ev) + [None] * (10 - len(ev))
                normalized_events.append((query, tuple(padded)))

        self.db.execute_batch_write(normalized_events)

    def get_events(self, limit=100, offset=0):
        """Retrieves file events sorted by newest first, support paging, filtered by active drives."""
        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
        query = f"""
            SELECT id, timestamp, event_type, src_path, dest_path, extension, file_size, incident_id,
                   sha256, process_name, process_pid, attribution_status
            FROM file_events
            WHERE {scope_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
        """
        params = list(scope_params) + [limit, offset]
        return self.db.execute_read(query, tuple(params))

    def get_events_by_incident(self, incident_id):
        """Retrieves all file events associated with a specific incident."""
        query = """
            SELECT id, timestamp, event_type, src_path, dest_path, extension, file_size,
                   sha256, process_name, process_pid, attribution_status
            FROM file_events
            WHERE incident_id = ?
            ORDER BY timestamp DESC, id DESC
        """
        return self.db.execute_read(query, (incident_id,))

    def get_total_events_count(self):
        """Gets total count of file events filtered by active drives."""
        scope_clause, scope_params = self.db.get_active_scope_clause("src_path")
        query = f"SELECT COUNT(*) as count FROM file_events WHERE {scope_clause}"
        row = self.db.execute_read_one(query, tuple(scope_params))
        return row["count"] if row else 0

    def prune_events(self, max_records=50000):
        """Deletes older file events to prevent infinite database growth."""
        # Find the threshold ID
        row = self.db.execute_read_one(
            "SELECT id FROM file_events ORDER BY timestamp DESC, id DESC LIMIT 1 OFFSET ?", 
            (max_records,)
        )
        if row:
            threshold_id = row["id"]
            self.db.execute_write("DELETE FROM file_events WHERE id <= ?", (threshold_id,))
            return True
        return False
