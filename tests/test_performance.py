import unittest
import os
import time
import tempfile
import psutil
from core.database.database import DatabaseManager
from core.monitoring.event_queue import EventQueue
from core.monitoring.monitor_manager import BatchProcessor
from core.detection.behavior_engine import BehaviorEngine
from core.database.events_repository import EventsRepository

class TestEDRPerformance(unittest.TestCase):
    def setUp(self):
        # Create a temp database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None
            
        self.queue = EventQueue()
        self.queue.clear()
        
        # Clear tables since DatabaseManager is a singleton and tests share the instance
        self.db.execute_write("DELETE FROM file_events")
        self.db.execute_write("DELETE FROM incidents")
        self.db.execute_write("DELETE FROM history_log")
        
        self.engine = BehaviorEngine(self.db, None)
        
        self.processor = BatchProcessor(self.queue, self.engine, self.db)
        # Block stats updates inside performance tests to avoid background polling
        self.processor.last_stats_emit = time.time() * 1000 + 1000000

    def tearDown(self):
        self.processor.stop()
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

    def run_event_storm(self, count):
        """Synthesizes high-volume event storm and measures processing latency."""
        # 1. Measure starting resources
        proc = psutil.Process(os.getpid())
        start_mem = proc.memory_info().rss / (1024 * 1024)
        
        # 2. Populate event queue
        # Normalized tuple structure: (event_type, src_path, dest_path, extension, file_size, incident_id)
        start_time = time.time()
        for i in range(count):
            self.queue.put(("MODIFY", f"C:\\data\\file_{i}.txt", None, ".txt", 1024, None))
            
        enqueue_duration = time.time() - start_time
        
        # Verify queue contains events
        self.assertEqual(self.queue.qsize(), count)

        # 3. Measure processing speed
        start_process_time = time.time()
        
        # Drain queue manually using the batch processor's logic to measure processing speed synchronously
        events_processed_count = 0
        while self.queue.qsize() > 0:
            batch = self.queue.get_batch(batch_size=200, timeout=0.01)
            if batch:
                self.processor._process_batch(batch)
                events_processed_count += len(batch)
                
        process_duration = time.time() - start_process_time
        
        # 4. Measure ending resources
        end_mem = proc.memory_info().rss / (1024 * 1024)
        mem_delta = end_mem - start_mem
        
        # 5. Output metrics
        throughput = events_processed_count / process_duration if process_duration > 0 else 0
        print(f"\n[PERFORMANCE TEST - {count} EVENTS]")
        print(f"  Enqueue Time:      {enqueue_duration:.3f}s")
        print(f"  Process Time:      {process_duration:.3f}s")
        print(f"  Throughput:        {throughput:.1f} events/sec")
        print(f"  Memory Delta:      {mem_delta:+.2f} MB")
        
        # Ensure database successfully persisted everything
        events_repo = EventsRepository(self.db)
        db_count = events_repo.get_total_events_count()
        self.assertEqual(db_count, count)
        
        # Performance threshold validations
        # Processing 1,000 events must be fast (< 3.5s in standard test runners)
        if count <= 1000:
            self.assertTrue(process_duration < 3.5, f"1000 events took too long: {process_duration:.2f}s")

    def test_performance_1000_events(self):
        self.run_event_storm(1000)

    def test_performance_5000_events(self):
        self.run_event_storm(5000)

    def test_performance_10000_events(self):
        self.run_event_storm(10000)

if __name__ == "__main__":
    unittest.main()
