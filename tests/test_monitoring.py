import unittest
import os
import time
import tempfile
from core.monitoring.event_queue import EventQueue
from core.monitoring.event_handler import FileSystemEventHandlerImpl
from core.monitoring.file_monitor import FileMonitor
from core.monitoring.process_monitor import ProcessMonitor
from core.monitoring.drive_manager import DriveManager

class TestMonitoringLayer(unittest.TestCase):
    def setUp(self):
        self.queue = EventQueue()
        self.queue.clear()
        self.handler = FileSystemEventHandlerImpl(self.queue)
        self.file_monitor = FileMonitor(self.handler)
        self.file_monitor.start()

    def tearDown(self):
        self.file_monitor.stop()

    def test_drive_manager_active_drives(self):
        drives = DriveManager.get_active_drives()
        self.assertTrue(len(drives) > 0)
        # Ensure letters are valid formats like "C:" or "D:"
        for d in drives:
            self.assertTrue(len(d["letter"]) >= 2)
            self.assertTrue(d["letter"].endswith(":"))

    def test_process_monitor_cache(self):
        proc_mon = ProcessMonitor(interval_sec=0.2)
        proc_mon._update_cache()
        
        # Current python process should be in cache
        my_pid = os.getpid()
        proc_info = proc_mon.get_process_info(my_pid)
        self.assertIsNotNone(proc_info)
        self.assertEqual(proc_info["pid"], my_pid)
        self.assertTrue("python" in proc_info["name"].lower())

    def test_file_watcher_detection(self):
        # Create temp folder to watch
        temp_dir = tempfile.mkdtemp()
        self.file_monitor.add_path(temp_dir, recursive=False)
        time.sleep(0.2) # Allow watchdog thread to boot and bind

        # Perform creations/modifications
        temp_file = os.path.join(temp_dir, "monitor_test_file.txt")
        with open(temp_file, "w") as f:
            f.write("test data")
            
        time.sleep(0.5) # Wait for events to populate queue
        
        # Read from EventQueue
        batch = self.queue.get_batch(batch_size=50)
        self.assertTrue(len(batch) > 0)
        
        # Check if we caught a CREATE or MODIFY event for our file
        found_test_event = False
        for ev in batch:
            event_type = ev[0]
            src_path = ev[1]
            extension = ev[3]
            file_size = ev[4]
            if "monitor_test_file.txt" in src_path:
                found_test_event = True
                self.assertEqual(extension, ".txt")
                
        self.assertTrue(found_test_event)

        # Cleanup
        try:
            os.remove(temp_file)
            os.rmdir(temp_dir)
        except PermissionError:
            pass

if __name__ == "__main__":
    unittest.main()
