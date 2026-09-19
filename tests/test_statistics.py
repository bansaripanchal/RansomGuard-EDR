import unittest
import os
import tempfile
import time
from core.database.database import DatabaseManager
from core.database.events_repository import EventsRepository
from core.database.incidents_repository import IncidentsRepository
from core.database.statistics_repository import StatisticsRepository

class TestEDRStatistics(unittest.TestCase):
    def setUp(self):
        DatabaseManager._instance = None
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None
            
        self.events_repo = EventsRepository(self.db)
        self.inc_repo = IncidentsRepository(self.db)
        self.stats_repo = StatisticsRepository(self.db)

    def tearDown(self):
        self.db.close_connection()
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
            if os.path.exists(self.db_path + "-wal"):
                os.remove(self.db_path + "-wal")
            if os.path.exists(self.db_path + "-shm"):
                os.remove(self.db_path + "-shm")
        except PermissionError:
            pass

    def test_statistics_retrieval(self):
        # 1. Populate some events and incidents
        self.events_repo.insert_event("CREATE", "C:\\data\\file1.txt")
        self.events_repo.insert_event("MODIFY", "C:\\data\\file1.txt")
        
        self.inc_repo.insert_incident(
            threat_name="Mass Rename", severity="CRITICAL", risk_score=95,
            affected_folder="C:\\data", detection_reason="Mass rename to locked extension"
        )
        self.inc_repo.insert_incident(
            threat_name="Mass Deletion", severity="MEDIUM", risk_score=50,
            affected_folder="C:\\data2", detection_reason="Mass delete"
        )
        
        # Resolve one threat
        rows = self.inc_repo.get_incidents()
        self.assertEqual(len(rows), 2)
        self.inc_repo.resolve_incident(rows[1]["id"]) # Resolve the medium risk incident

        # 2. Assert stats counts match
        summary = self.stats_repo.get_dashboard_summary()
        self.assertEqual(summary["events_today_total"], 1)
        self.assertEqual(summary["events_today_created"], 1)
        self.assertEqual(summary["events_today_modified"], 1)
        self.assertEqual(summary["incidents_total"], 2)
        self.assertEqual(summary["incidents_active"], 1) # Critical one is active
        self.assertEqual(summary["incidents_blocked"], 1) # Medium one resolved/blocked

        # 3. Assert severity distribution matches
        dist = self.stats_repo.get_incident_severity_distribution()
        self.assertEqual(dist["CRITICAL"], 1)
        self.assertEqual(dist["MEDIUM"], 1)
        self.assertEqual(dist["HIGH"], 0)
        self.assertEqual(dist["LOW"], 0)

    def test_weekly_activity(self):
        # Insert events matching active drive letter
        self.events_repo.insert_event("CREATE", "C:\\data\\file1.txt")
        self.events_repo.insert_event("MODIFY", "C:\\data\\file2.txt")
        
        activity = self.stats_repo.get_weekly_activity()
        self.assertEqual(len(activity), 7)
        total_events = sum(activity.values())
        self.assertEqual(total_events, 2)

if __name__ == "__main__":
    unittest.main()
