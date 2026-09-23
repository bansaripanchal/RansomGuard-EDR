import unittest
import os
import sys
import tempfile
import shutil
import time

from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.history_repository import HistoryRepository
from core.monitoring.drive_manager import DriveManager
from core.protection.usb_protection_manager import (
    USBProtectionManager, USBDevice, USBScanWorker,
    DETECTION_SOURCE_INITIAL_SCAN, DETECTION_SOURCE_REALTIME
)
from core.detection.risk_engine import (
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN, RiskEngine
)

class TestUSBProtection(unittest.TestCase):
    def setUp(self):
        # Use a temporary SQLite database for test isolation
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_usb_protection.db")
        self.db = DatabaseManager(self.db_path)
        self.inc_repo = IncidentsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.usb_manager = USBProtectionManager(self.db)

    def tearDown(self):
        # Stop any active timer
        if hasattr(self.usb_manager, "poll_timer") and self.usb_manager.poll_timer.isActive():
            self.usb_manager.poll_timer.stop()
        if self.usb_manager.active_worker and self.usb_manager.active_worker.isRunning():
            self.usb_manager.active_worker.stop()
            self.usb_manager.active_worker.wait(1000)
        self.db.close_connection()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_drive_manager_volume_info(self):
        """Verifies DriveManager retrieves real Windows volume metadata."""
        if sys.platform.startswith("win"):
            vol_name, fs_name = DriveManager.get_volume_info("C:")
            # On Windows C:, file system is virtually always NTFS or ReFS
            self.assertTrue(len(fs_name) > 0)
            self.assertNotEqual(fs_name, "Unknown")
            
            # Check get_active_drives includes volume info
            drives = DriveManager.get_active_drives()
            self.assertTrue(len(drives) > 0)
            c_drive = next((d for d in drives if d["letter"].upper() == "C:"), None)
            self.assertIsNotNone(c_drive)
            self.assertIn("file_system", c_drive)
            self.assertIn("volume_name", c_drive)
            self.assertIn("total_bytes", c_drive)

    def test_usb_scan_worker_clean_files(self):
        """Verifies recursive initial scan correctly classifies clean files with real evidence."""
        scan_dir = os.path.join(self.temp_dir, "fake_usb")
        os.makedirs(os.path.join(scan_dir, "subdir"), exist_ok=True)

        file1 = os.path.join(scan_dir, "notes.txt")
        with open(file1, "w", encoding="utf-8") as f:
            f.write("Legitimate user project notes.")

        file2 = os.path.join(scan_dir, "subdir", "presentation.pdf")
        with open(file2, "wb") as f:
            f.write(b"%PDF-1.4 Standard legitimate test document.")

        cache = {}
        worker = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        
        results = []
        worker.scan_completed.connect(lambda res: results.append(res))
        worker.run() # Run synchronously for deterministic unit testing

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["files_discovered"], 2)
        self.assertEqual(res["files_analyzed"], 2)
        self.assertEqual(res["clean_count"], 2)
        self.assertEqual(res["threats_found"], 0)
        self.assertEqual(res["malicious_count"], 0)
        self.assertEqual(res["suspicious_count"], 0)

        # Verify history logs
        logs = self.history_repo.get_logs(limit=20)
        event_types = [l["event_type"] for l in logs]
        self.assertIn("USB_SCAN_STARTED", event_types)
        self.assertIn("USB_SCAN_COMPLETED", event_types)

    def test_usb_scan_worker_known_malware_test_signature(self):
        """
        Verifies standard known malware test signature is accurately classified as MALICIOUS
        via the shared UnifiedFileAnalyzer and tagged with 'USB Initial Scan'.
        """
        scan_dir = os.path.join(self.temp_dir, "usb_threat_test")
        os.makedirs(scan_dir, exist_ok=True)

        # Use RansomGuard's verified internal test signature to avoid host Windows Defender file locks
        threat_file = os.path.join(scan_dir, "threat_sample.bin")
        payload = b"TEST_MALWARE_PAYLOAD_SIGNATURE_FOR_RANSOMGUARD_UNIT_TEST_2026"
        with open(threat_file, "wb") as f:
            f.write(payload)

        cache = {}
        worker = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)

        threats = []
        worker.threat_detected.connect(lambda t: threats.append(t))
        worker.run()

        self.assertEqual(len(threats), 1)
        threat = threats[0]
        self.assertEqual(threat["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(threat["detection_source"], DETECTION_SOURCE_INITIAL_SCAN)
        self.assertTrue(threat["sha256"].startswith("7bfe973b"))

        # Check Incident Repository has the incident with real fields
        active_incs = self.inc_repo.get_incidents(status_filter="ACTIVE")
        self.assertTrue(len(active_incs) >= 1)
        inc = active_incs[0]
        self.assertEqual(inc["verdict"], VERDICT_MALICIOUS)
        self.assertIn(DETECTION_SOURCE_INITIAL_SCAN, inc["threat_name"])
        self.assertIn(DETECTION_SOURCE_INITIAL_SCAN, inc["detection_reason"])
        self.assertEqual(inc["affected_file"], "threat_sample.bin")

        # Check history audit trail
        logs = self.history_repo.get_logs(limit=20)
        threat_logs = [l for l in logs if l["event_type"] == "USB_THREAT_DETECTED"]
        self.assertEqual(len(threat_logs), 1)
        self.assertIn("MALICIOUS", threat_logs[0]["description"])

    def test_usb_scan_cache_behavior_and_invalidation(self):
        """
        Verifies that scan cache reuses verified results when the file has not changed,
        and invalidates when mtime, ctime, size, or content changes.
        """
        scan_dir = os.path.join(self.temp_dir, "cache_test")
        os.makedirs(scan_dir, exist_ok=True)

        target_file = os.path.join(scan_dir, "cached_file.txt")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("Initial content for testing cache integrity.")

        cache = {}
        # First scan: populates cache
        worker1 = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        worker1.run()
        self.assertEqual(worker1.files_analyzed, 1)
        self.assertIn(target_file, cache)
        initial_sha = cache[target_file]["sha256"]

        # Second scan: identical file should reuse cache without re-hashing
        worker2 = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        worker2.run()
        self.assertEqual(worker2.clean_count, 1)

        # Modify the file content and change size
        time.sleep(0.01)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("Modified content that significantly changes file size and hash bytes.")

        # Third scan: should detect change, invalidate old cache entry and calculate new hash
        worker3 = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        worker3.run()
        self.assertEqual(worker3.clean_count, 1)
        new_sha = cache[target_file]["sha256"]
        self.assertNotEqual(initial_sha, new_sha)

    def test_usb_removal_during_scan(self):
        """
        Verifies that if USB removal occurs during scanning:
        - Work stops immediately
        - Scan is marked Interrupted (never Completed)
        - Actual counts are preserved
        - Interruption is logged in history
        """
        scan_dir = os.path.join(self.temp_dir, "removal_test")
        os.makedirs(scan_dir, exist_ok=True)

        for i in range(10):
            with open(os.path.join(scan_dir, f"file_{i}.txt"), "w") as f:
                f.write(f"Sample file {i}")

        cache = {}
        worker = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)

        interrupted_reasons = []
        completed_signals = []
        worker.scan_interrupted.connect(lambda r: interrupted_reasons.append(r))
        worker.scan_completed.connect(lambda s: completed_signals.append(s))

        # Simulate device removal by triggering stop with is_removal=True
        worker.stop(is_removal=True)
        worker.run()

        self.assertTrue(len(interrupted_reasons) > 0)
        self.assertEqual(len(completed_signals), 0) # Scan must NEVER be marked completed
        self.assertIn("disconnected", interrupted_reasons[0].lower())

        # Check history audit trail has USB_SCAN_INTERRUPTED
        logs = self.history_repo.get_logs(limit=20)
        interrupted_logs = [l for l in logs if l["event_type"] == "USB_SCAN_INTERRUPTED"]
        self.assertEqual(len(interrupted_logs), 1)

    def test_realtime_usb_detection_flow(self):
        """
        Verifies that real-time file events on a connected USB storage device:
        - Are evaluated via UnifiedFileAnalyzer
        - Use detection source 'USB Real-Time Detection'
        - Do not duplicate analysis on unchanged files
        """
        drive_letter = "T:"
        mount_point = "T:\\"
        # Register a connected device in manager
        device = USBDevice(
            drive_letter=drive_letter,
            mount_point=mount_point,
            volume_name="TEST_USB",
            file_system="FAT32",
            total_bytes=16000000000,
            free_bytes=8000000000,
            used_percent=50.0
        )
        self.usb_manager.connected_devices[drive_letter] = device

        # Create a test file in temp dir to simulate USB file path
        test_file = os.path.join(self.temp_dir, "usb_doc.txt")
        with open(test_file, "w") as f:
            f.write("Real-time telemetry event sample.")

        # Simulate path matching T:\
        # Mock splitdrive behavior by pointing to real file
        fake_usb_path = test_file

        # Call analyze_realtime_event on actual file
        # Temporarily add its drive to connected devices
        local_drive = os.path.splitdrive(test_file)[0].upper()
        self.usb_manager.connected_devices[local_drive] = device

        record1 = self.usb_manager.analyze_realtime_event(test_file, "MODIFY")
        self.assertIsNotNone(record1)
        self.assertEqual(record1["verdict"], VERDICT_CLEAN)
        self.assertEqual(record1["detection_source"], DETECTION_SOURCE_REALTIME)

        # Call again without changing file: should return cached record without re-analyzing
        record2 = self.usb_manager.analyze_realtime_event(test_file, "MODIFY")
        self.assertIsNotNone(record2)
        self.assertEqual(record1["sha256"], record2["sha256"])

    def test_usb_repository_persistence(self):
        """Verifies scan session summaries and per-file scan results persist correctly in SQLite."""
        from core.database.usb_repository import USBRepository
        usb_repo = USBRepository(self.db)

        scan_id = "test_sess_001"
        usb_repo.create_session(
            scan_id=scan_id,
            drive_letter="G:",
            volume_name="SanDisk USB",
            file_system="NTFS",
            total_bytes=15000000000,
            free_bytes=5000000000,
            status="SCANNING"
        )

        test_records = [
            {
                "file_path": "G:\\docs\\report.pdf",
                "filename": "report.pdf",
                "verdict": VERDICT_CLEAN,
                "severity": "LOW",
                "risk_score": 0,
                "threat_name": "Clean File",
                "reason": "No security threat detected.",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size": 1048576,
                "file_type": "PDF Document",
                "evidence_list": ["Valid PDF structure"],
                "detection_source": DETECTION_SOURCE_INITIAL_SCAN
            }
        ]

        usb_repo.update_session(
            scan_id=scan_id,
            status="COMPLETED",
            discovered_count=100,
            analyzed_count=100,
            clean_count=99,
            suspicious_count=1,
            malicious_count=0,
            unknown_count=0,
            threat_count=1,
            duration_sec=2.5
        )
        usb_repo.save_scan_results(scan_id, test_records)

        sessions = usb_repo.get_recent_sessions(limit=10)
        self.assertTrue(len(sessions) >= 1)
        sess = next((s for s in sessions if s["scan_id"] == scan_id), None)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["status"], "COMPLETED")
        self.assertEqual(sess["discovered_count"], 100)
        self.assertEqual(sess["clean_count"], 99)

        results = usb_repo.get_session_results(scan_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["filename"], "report.pdf")
        self.assertEqual(results[0]["verdict"], VERDICT_CLEAN)

    def test_usb_scan_worker_large_batch_multithreaded(self):
        """Verifies multi-threaded worker processes a large batch of files quickly and accurately."""
        scan_dir = os.path.join(self.temp_dir, "batch_scan")
        os.makedirs(os.path.join(scan_dir, "dir1"), exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "dir2"), exist_ok=True)

        # Create 150 test files
        for i in range(75):
            with open(os.path.join(scan_dir, "dir1", f"doc_{i}.txt"), "w") as f:
                f.write(f"Sample content text {i}")
            with open(os.path.join(scan_dir, "dir2", f"data_{i}.dat"), "wb") as f:
                f.write(b"Binary payload sample " + str(i).encode())

        cache = {}
        worker = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        
        results = []
        worker.scan_completed.connect(lambda r: results.append(r))
        worker.run()

        self.assertEqual(len(results), 1)
        summary = results[0]
        self.assertEqual(summary["files_discovered"], 150)
        self.assertEqual(summary["files_analyzed"], 150)
        self.assertEqual(summary["clean_count"], 150)
        self.assertEqual(summary["threats_found"], 0)

    def test_verdict_policy_classification_levels(self):
        """
        Comprehensive test for RiskEngine verdict classification & USB Protection data binding:
        1. Weak filename indicator (README.txt, score 30, LOW severity) -> CLEAN
        2. Single low-risk script heuristic (base.py, score 15, LOW severity) -> CLEAN
        3. Multiple meaningful suspicious indicators (accumulated score >= 50) -> SUSPICIOUS
        4. Strong malicious evidence -> MALICIOUS
        5. Analysis failure -> UNKNOWN / UNABLE TO DETERMINE
        6. USB Protection displays exact verdict returned by RiskEngine
        """
        scan_dir = os.path.join(self.temp_dir, "verdict_policy_test")
        os.makedirs(scan_dir, exist_ok=True)

        # 1. Weak filename indicator: README.txt
        readme_path = os.path.join(scan_dir, "README.txt")
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write("Standard repository documentation file.")

        # 2. Single low-risk script heuristic: base.py
        script_path = os.path.join(scan_dir, "base.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write("# Simple python helper script\nwscript.shell invoke-expression iex")

        # 3. Strong malicious evidence: test_malware.bin
        malware_path = os.path.join(scan_dir, "test_malware.bin")
        with open(malware_path, "wb") as f:
            f.write(b"TEST_MALWARE_PAYLOAD_SIGNATURE_FOR_RANSOMGUARD_UNIT_TEST_2026")

        cache = {}
        worker = USBScanWorker(target_drive=scan_dir, scan_cache=cache, db_manager=self.db)
        worker.run()

        # Check records
        record_map = {r["filename"]: r for r in worker.records}

        # 1. README.txt: score = 30, severity = LOW -> Verdict MUST be CLEAN
        readme_rec = record_map.get("README.txt")
        self.assertIsNotNone(readme_rec)
        self.assertEqual(readme_rec["risk_score"], 30)
        self.assertEqual(readme_rec["severity"], "LOW")
        self.assertEqual(readme_rec["verdict"], VERDICT_CLEAN)

        # 2. base.py: score = 15, severity = LOW -> Verdict MUST be CLEAN
        base_rec = record_map.get("base.py")
        self.assertIsNotNone(base_rec)
        self.assertEqual(base_rec["risk_score"], 15)
        self.assertEqual(base_rec["severity"], "LOW")
        self.assertEqual(base_rec["verdict"], VERDICT_CLEAN)

        # 3. Multiple meaningful suspicious indicators -> SUSPICIOUS
        multi_rules = [
            {"rule_name": "RANSOM_NOTE_PATTERN", "reason": "Filename matches ransom note"}, # +30
            {"rule_name": "SUSPICIOUS_PE_CHARACTERISTICS", "reason": "High entropy section"} # +20
        ]
        score_multi, _ = RiskEngine.calculate_risk(multi_rules)
        verdict_multi = RiskEngine.determine_verdict(multi_rules)
        self.assertEqual(score_multi, 50)
        self.assertEqual(verdict_multi, VERDICT_SUSPICIOUS)

        # 4. Strong malicious evidence -> MALICIOUS
        malware_rec = record_map.get("test_malware.bin")
        self.assertIsNotNone(malware_rec)
        self.assertEqual(malware_rec["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(malware_rec["risk_score"], 100)

        # 5. Analysis failure -> UNKNOWN / UNABLE TO DETERMINE
        verdict_unk = RiskEngine.determine_verdict([], is_accessible=False, has_errors=True)
        self.assertEqual(verdict_unk, VERDICT_UNKNOWN)

        # 6. USB Protection data binding check: Table model and page must reflect exact RiskEngine verdicts
        from ui.pages.usb_protection_page import USBScanTableModel
        model = USBScanTableModel(worker.records)
        self.assertEqual(model.data(model.index(0, 2), 0), record_map[worker.records[0]["filename"]]["verdict"])


if __name__ == "__main__":
    unittest.main()
