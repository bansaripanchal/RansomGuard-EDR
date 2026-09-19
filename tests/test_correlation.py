import unittest
import os
import tempfile
import time
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository
from core.detection.behavior_engine import BehaviorEngine

class TestEDRCorrelation(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None
            
        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)
        
        # Clear tables since DatabaseManager is a singleton and tests share the instance
        self.db.execute_write("DELETE FROM file_events")
        self.db.execute_write("DELETE FROM incidents")
        self.db.execute_write("DELETE FROM history_log")
        
        self.engine = BehaviorEngine(self.db, None)

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

    def test_single_incident_coalescing(self):
        # 1. Simulate a batch of events in folder A
        batch1 = []
        for i in range(25): # Exceeds MODIFY threshold (20) -> triggers risk 40
            batch1.append(("MODIFY", f"C:\\folderA\\file_{i}.txt", None, ".txt", 1024, None))
        
        incidents1 = self.engine.process_new_events(batch1)
        self.assertEqual(len(incidents1), 1) # Created a new incident
        inc_data1, is_new1 = incidents1[0]
        self.assertTrue(is_new1)
        self.assertEqual(inc_data1["affected_folder"], "C:\\folderA")
        self.assertEqual(inc_data1["modified_count"], 25)

        # 2. Simulate subsequent changes in the same folder A within the window
        # Clear in-memory event window to simulate separate event storm intervals, 
        # but SQLite persistent correlation remains active (60 seconds threshold)
        self.engine.event_window.clear()
        
        batch2 = []
        for i in range(25): # Exceeds RENAME threshold (20) -> triggers risk 60
            batch2.append(("RENAME", f"C:\\folderA\\file_{i}.txt", f"C:\\folderA\\file_{i}.locked", ".locked", 2048, None))
            
        incidents2 = self.engine.process_new_events(batch2)
        self.assertEqual(len(incidents2), 1)
        inc_data2, is_new2 = incidents2[0]
        self.assertFalse(is_new2) # Should be coalesced (updated, not new)
        self.assertEqual(inc_data2["id"], inc_data1["id"]) # Same ID
        # Total counts should be updated
        self.assertEqual(inc_data2["modified_count"], 25)
        self.assertEqual(inc_data2["renamed_count"], 25)

    def test_independent_threats_separation(self):
        # 1. Simulate mass modification in folder A
        batchA = [("MODIFY", f"C:\\folderA\\file_{i}.txt", None, ".txt", 1024, None) for i in range(25)]
        incidentsA = self.engine.process_new_events(batchA)
        self.assertEqual(len(incidentsA), 1)
        
        # 2. Simulate mass renaming in folder B (independent directory tree)
        self.engine.event_window.clear()
        
        batchB = [("RENAME", f"C:\\folderB\\file_{i}.txt", f"C:\\folderB\\file_{i}.locked", ".locked", 2048, None) for i in range(25)]
        incidentsB = self.engine.process_new_events(batchB)
        self.assertEqual(len(incidentsB), 1)
        
        inc_dataA = incidentsA[0][0]
        inc_dataB = incidentsB[0][0]
        
        # Threat repositories must retain them as separate alerts
        self.assertNotEqual(inc_dataA["id"], inc_dataB["id"])
        self.assertEqual(inc_dataA["affected_folder"], "C:\\folderA")
        self.assertEqual(inc_dataB["affected_folder"], "C:\\folderB")

if __name__ == "__main__":
    unittest.main()
