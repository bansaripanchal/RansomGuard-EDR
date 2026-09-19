import unittest
import os
import tempfile
import sqlite3
from core.database.database import DatabaseManager
from core.database.settings_repository import SettingsRepository
from core.database.events_repository import EventsRepository
from core.database.incidents_repository import IncidentsRepository
from core.database.statistics_repository import StatisticsRepository
from core.database.history_repository import HistoryRepository

class TestDatabaseLayer(unittest.TestCase):
    def setUp(self):
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        # Initialize DatabaseManager
        self.db = DatabaseManager(self.db_path)
        # Ensure we clear thread-local cached connection to force using the new path
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None

    def tearDown(self):
        # Close connection and cleanup files
        self.db.close_connection()
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
            # Remove WAL files if they exist
            if os.path.exists(self.db_path + "-wal"):
                os.remove(self.db_path + "-wal")
            if os.path.exists(self.db_path + "-shm"):
                os.remove(self.db_path + "-shm")
        except PermissionError:
            pass

    def test_wal_mode_enabled(self):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_settings_repository(self):
        repo = SettingsRepository(self.db)
        repo.set_setting("test_key", "test_value")
        val = repo.get_setting("test_key")
        self.assertEqual(val, "test_value")

        # Test monitored paths
        repo.add_monitored_path("C:\\monitored\\path", recursive=True)
        paths = repo.get_monitored_paths()
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["path"], "C:\\monitored\\path")
        self.assertTrue(paths[0]["recursive"])

        repo.remove_monitored_path("C:\\monitored\\path")
        paths = repo.get_monitored_paths()
        self.assertEqual(len(paths), 0)

    def test_events_and_statistics(self):
        events_repo = EventsRepository(self.db)
        stats_repo = StatisticsRepository(self.db)
        inc_repo = IncidentsRepository(self.db)

        # Confirm zero counts
        summary = stats_repo.get_dashboard_summary()
        self.assertEqual(summary["events_today_total"], 0)

        # Batch insert events
        events_to_insert = [
            ("CREATE", "C:\\test\\file1.txt", None, ".txt", 1024, None),
            ("MODIFY", "C:\\test\\file1.txt", None, ".txt", 2048, None),
            ("RENAME", "C:\\test\\file1.txt", "C:\\test\\file1.locked", ".locked", 2048, None),
            ("DELETE", "C:\\test\\file1.locked", None, ".locked", 0, None)
        ]
        events_repo.insert_events_batch(events_to_insert)

        summary = stats_repo.get_dashboard_summary()
        self.assertEqual(summary["events_today_total"], 2)
        self.assertEqual(summary["events_today_created"], 1)
        self.assertEqual(summary["events_today_modified"], 1)
        self.assertEqual(summary["events_today_renamed"], 1)
        self.assertEqual(summary["events_today_deleted"], 1)

        # Check hourly stats
        hourly = stats_repo.get_hourly_activity_today()
        self.assertEqual(len(hourly), 24)
        active_hours = [h for h, count in hourly.items() if count > 0]
        self.assertEqual(len(active_hours), 1)

    def test_incidents_and_correlation(self):
        inc_repo = IncidentsRepository(self.db)
        events_repo = EventsRepository(self.db)

        # Create incident
        inc_id = inc_repo.insert_incident(
            threat_name="Ransomware Test",
            severity="HIGH",
            risk_score=85,
            affected_folder="C:\\data",
            detection_reason="Mass modification",
            recommendation="Inspect file activity"
        )
        self.assertTrue(inc_id > 0)

        # Test active incident lookup
        active_inc = inc_repo.get_active_incident_by_folder("C:\\data", age_seconds=5)
        self.assertIsNotNone(active_inc)
        self.assertEqual(active_inc["id"], inc_id)
        self.assertEqual(active_inc["severity"], "HIGH")

        # Test counts updates
        inc_repo.update_incident_counts(inc_id, created_add=5, modified_add=10, risk_score=95, severity="CRITICAL")
        updated_inc = inc_repo.get_incident(inc_id)
        self.assertEqual(updated_inc["created_count"], 5)
        self.assertEqual(updated_inc["modified_count"], 10)
        self.assertEqual(updated_inc["risk_score"], 95)
        self.assertEqual(updated_inc["severity"], "CRITICAL")

        # Associate file events with incident
        events_repo.insert_event("CREATE", "C:\\data\\f1.txt", incident_id=inc_id)
        events_repo.insert_event("MODIFY", "C:\\data\\f1.txt", incident_id=inc_id)

        inc_events = events_repo.get_events_by_incident(inc_id)
        self.assertEqual(len(inc_events), 2)

if __name__ == "__main__":
    unittest.main()
