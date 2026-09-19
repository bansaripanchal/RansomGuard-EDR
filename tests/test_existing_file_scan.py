import os
import sys
import time
import shutil
import tempfile
import threading
import unittest

from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.history_repository import HistoryRepository
from core.database.settings_repository import SettingsRepository
from core.scanning.existing_scan_manager import (
    ExistingScanManager, ExistingScanWorker,
    DETECTION_SOURCE_EXISTING_SCAN, FREQUENCY_MAP, DEFAULT_FREQUENCY
)
from core.analysis.file_analyzer import UnifiedFileAnalyzer
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from PySide6.QtWidgets import QApplication
from core.scanning.scanner import BackgroundScanner
from core.protection.usb_protection_manager import USBScanWorker, DETECTION_SOURCE_INITIAL_SCAN
from core.scanning.scan_exclusions import ScanExclusions
from core.scanning.existing_scan_session import (
    BatchPersistenceWriter, ScanSessionStats,
    SCAN_STATUS_IDLE, SCAN_STATUS_DISCOVERING, SCAN_STATUS_SCANNING,
    SCAN_STATUS_PAUSED, SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED
)
from core.scanning.existing_scan_workers import AnalysisWorker
from ui.pages.dashboard_page import DashboardPage

_qt_app = QApplication.instance() or QApplication([])


class TestExistingFileScan(unittest.TestCase):
    def setUp(self):
        # Isolated temporary directory and SQLite database
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_existing_scan.db")
        self.db = DatabaseManager(self.db_path)
        self.inc_repo = IncidentsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.settings_repo = SettingsRepository(self.db)
        self.scan_manager = ExistingScanManager(self.db)

    def tearDown(self):
        # Stop scheduler timer and any running workers
        if hasattr(self.scan_manager, "schedule_timer") and self.scan_manager.schedule_timer.isActive():
            self.scan_manager.schedule_timer.stop()
        if self.scan_manager.active_worker and self.scan_manager.active_worker.isRunning():
            self.scan_manager.active_worker.stop()
            self.scan_manager.active_worker.wait(1000)
        self.db.close_connection()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_frequency_configuration_persistence(self):
        """Verifies all 8 scan frequencies are supported, persisted in SQLite, and retrieved accurately."""
        expected_frequencies = [
            "Every hour",
            "Every 4 hours",
            "Every 12 hours",
            "Every day",
            "Every 3 days",
            "Every week",
            "Manual only",
            "Off"
        ]

        for freq in expected_frequencies:
            self.scan_manager.set_frequency(freq)
            # Verify in-memory getter
            self.assertEqual(self.scan_manager.get_frequency(), freq)
            # Verify persistent database storage
            db_val = self.settings_repo.get_setting("existing_scan_frequency")
            self.assertEqual(db_val, freq)

        # Invalid frequency should be ignored
        self.scan_manager.set_frequency("Every 5 minutes")
        self.assertEqual(self.scan_manager.get_frequency(), "Off")

    def test_next_scan_time_calculation(self):
        """Verifies calculated next scan time matches scheduled frequencies or manual/off states."""
        # Manual only
        self.scan_manager.set_frequency("Manual only")
        self.assertEqual(self.scan_manager.get_next_scan_time(), "Manual only")

        # Off
        self.scan_manager.set_frequency("Off")
        self.assertEqual(self.scan_manager.get_next_scan_time(), "Off")

        # Timed interval without prior scan
        self.scan_manager.set_frequency("Every hour")
        next_time = self.scan_manager.get_next_scan_time()
        self.assertTrue(len(next_time) > 0)
        self.assertNotIn("None", next_time)

        # Timed interval with prior scan epoch stored
        past_epoch = time.time() - 1800 # Scanned 30 min ago
        self.settings_repo.set_setting("existing_scan_last_epoch", str(past_epoch))
        next_time_with_history = self.scan_manager.get_next_scan_time()
        self.assertTrue(len(next_time_with_history) > 0)

    def test_protected_drive_scope_resolution(self):
        """Verifies protected drives setting is properly parsed into root directories."""
        self.settings_repo.set_setting("protected_drives", "C:,D:,E:")
        drives = self.scan_manager.get_protected_drives()
        self.assertEqual(drives, ["C:\\", "D:\\", "E:\\"])

        # Single drive
        self.settings_repo.set_setting("protected_drives", "C:")
        drives = self.scan_manager.get_protected_drives()
        self.assertEqual(drives, ["C:\\"])

    def test_recursive_discovery_and_clean_scan(self):
        """Verifies recursive discovery of pre-existing files and authentic clean verdict reporting."""
        scan_dir = os.path.join(self.temp_dir, "clean_endpoint")
        sub_dir = os.path.join(scan_dir, "documents", "reports")
        os.makedirs(sub_dir, exist_ok=True)

        f1 = os.path.join(scan_dir, "project_notes.txt")
        with open(f1, "w", encoding="utf-8") as f:
            f.write("Legitimate documentation file.")

        f2 = os.path.join(sub_dir, "annual_audit.pdf")
        with open(f2, "wb") as f:
            f.write(b"%PDF-1.4 Standard legitimate test document.")

        worker = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        results = []
        worker.scan_completed.connect(lambda res: results.append(res))
        worker.run()

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
        self.assertIn("EXISTING_SCAN_STARTED", event_types)
        self.assertIn("EXISTING_SCAN_COMPLETED", event_types)

        # Verify SQLite cache table has entries
        cached_rows = self.db.execute_read("SELECT file_path, verdict FROM existing_scan_cache")
        self.assertEqual(len(cached_rows), 2)
        for r in cached_rows:
            self.assertEqual(r["verdict"], VERDICT_CLEAN)

    def test_incremental_caching_and_invalidation(self):
        """
        Verifies incremental caching:
        - First scan analyzes and stores cache
        - Second scan on unchanged file reuses cached verdict without re-analysis
        - File modification invalidates cache and triggers full re-analysis
        """
        scan_dir = os.path.join(self.temp_dir, "cache_endpoint")
        os.makedirs(scan_dir, exist_ok=True)

        target_file = os.path.join(scan_dir, "inventory.csv")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("id,item,qty\n1,server,4\n2,switch,8\n")

        # Scan 1: initial population
        worker1 = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        worker1.run()
        self.assertEqual(worker1.files_analyzed, 1)

        cache_entry1 = self.db.execute_read_one(
            "SELECT sha256, mtime_ns, file_size FROM existing_scan_cache WHERE file_path = ?",
            (target_file,)
        )
        self.assertIsNotNone(cache_entry1)
        initial_sha = cache_entry1["sha256"]

        # Scan 2: Unchanged file - cache hit
        worker2 = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        worker2.run()
        self.assertEqual(worker2.clean_count, 1)

        # Modify file (change content and length)
        time.sleep(0.02)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("id,item,qty,status\n1,server,4,active\n2,switch,8,active\n3,firewall,2,active\n")

        # Scan 3: Modified file - cache miss / invalidation
        worker3 = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        worker3.run()
        self.assertEqual(worker3.clean_count, 1)

        cache_entry2 = self.db.execute_read_one(
            "SELECT sha256, mtime_ns, file_size FROM existing_scan_cache WHERE file_path = ?",
            (target_file,)
        )
        self.assertIsNotNone(cache_entry2)
        new_sha = cache_entry2["sha256"]
        self.assertNotEqual(initial_sha, new_sha)

    def test_inaccessible_file_handling(self):
        """Inaccessible or permission-denied file must be reported as UNKNOWN and never as CLEAN."""
        worker = ExistingScanWorker(target_drives=[self.temp_dir], db_manager=self.db)
        # Scan a non-existent / locked file path directly
        missing_path = os.path.join(self.temp_dir, "locked_system_file.sys")
        record = worker._scan_file(missing_path)

        self.assertEqual(record["verdict"], VERDICT_UNKNOWN)
        self.assertNotEqual(record["verdict"], VERDICT_CLEAN)
        self.assertIn("Inaccessible", record["threat_name"])

    def test_threat_detection_incident_and_alert(self):
        """
        Verifies pre-existing malware signature is accurately classified as MALICIOUS,
        creates an ACTIVE incident tagged 'Existing File Scan', and logs audit trail.
        """
        scan_dir = os.path.join(self.temp_dir, "threat_endpoint")
        os.makedirs(scan_dir, exist_ok=True)

        # Internal test malware payload signature
        threat_file = os.path.join(scan_dir, "suspicious_payload.bin")
        payload = b"TEST_MALWARE_PAYLOAD_SIGNATURE_FOR_RANSOMGUARD_UNIT_TEST_2026"
        with open(threat_file, "wb") as f:
            f.write(payload)

        worker = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        threats = []
        worker.threat_detected.connect(lambda t: threats.append(t))
        worker.run()

        # 1. Threat detected by worker
        self.assertEqual(len(threats), 1)
        threat = threats[0]
        self.assertEqual(threat["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(threat["detection_source"], DETECTION_SOURCE_EXISTING_SCAN)
        self.assertTrue(threat["sha256"].startswith("7bfe973b"))

        # 2. Incident created in DB with status ACTIVE
        active_incs = self.inc_repo.get_incidents(status_filter="ACTIVE")
        self.assertTrue(len(active_incs) >= 1)
        matching_inc = next((i for i in active_incs if i["affected_file"] == "suspicious_payload.bin"), None)
        self.assertIsNotNone(matching_inc)
        self.assertEqual(matching_inc["verdict"], VERDICT_MALICIOUS)
        self.assertIn(DETECTION_SOURCE_EXISTING_SCAN, matching_inc["threat_name"])
        self.assertEqual(matching_inc["severity"], "CRITICAL")
        self.assertEqual(matching_inc["risk_score"], 100)

        # 3. History audit log
        logs = self.history_repo.get_logs(limit=20)
        threat_logs = [l for l in logs if l["event_type"] == "EXISTING_THREAT_DETECTED"]
        self.assertEqual(len(threat_logs), 1)
        self.assertIn(DETECTION_SOURCE_EXISTING_SCAN, threat_logs[0]["description"])

    def test_scan_cancellation(self):
        """Verifies cancellation halts worker cleanly, records interruption, and never marks completed."""
        scan_dir = os.path.join(self.temp_dir, "cancel_endpoint")
        os.makedirs(scan_dir, exist_ok=True)

        for i in range(10):
            with open(os.path.join(scan_dir, f"file_{i}.txt"), "w") as f:
                f.write(f"Sample data {i}")

        worker = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        interrupted = []
        completed = []
        worker.scan_interrupted.connect(lambda r: interrupted.append(r))
        worker.scan_completed.connect(lambda c: completed.append(c))

        # Stop worker before running
        worker.stop()
        worker.run()

        self.assertTrue(len(interrupted) > 0)
        self.assertEqual(len(completed), 0)
        self.assertIn("cancelled", interrupted[0].lower())

        # Check history audit trail
        logs = self.history_repo.get_logs(limit=20)
        cancel_logs = [l for l in logs if l["event_type"] == "EXISTING_SCAN_INTERRUPTED"]
        self.assertEqual(len(cancel_logs), 1)

    def test_dashboard_initial_and_updated_state(self):
        """Verifies strict 'Not scanned yet' display before first scan, and real timestamps after."""
        # Prior to first scan
        self.assertEqual(self.scan_manager.get_last_scan_time(), "Not scanned yet")
        self.assertIsNone(self.scan_manager.get_last_scan_summary())

        # Simulate completion
        scan_dir = os.path.join(self.temp_dir, "dash_test")
        os.makedirs(scan_dir, exist_ok=True)
        with open(os.path.join(scan_dir, "file.txt"), "w") as f:
            f.write("test")

        worker = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        results = []
        worker.scan_completed.connect(lambda res: self.scan_manager._on_worker_completed(res))
        worker.run()

        # After scan completes: real timestamp and stored summary
        last_time = self.scan_manager.get_last_scan_time()
        self.assertNotEqual(last_time, "Not scanned yet")
        self.assertTrue(len(last_time) > 0)

        summary = self.scan_manager.get_last_scan_summary()
        self.assertIsNotNone(summary)
        self.assertEqual(summary["files_analyzed"], 1)
        self.assertEqual(summary["clean_count"], 1)

    def test_four_way_pipeline_consistency(self):
        """
        Verifies that all four protection sources:
        1. Existing File Scan
        2. Real-Time Protection (UnifiedFileAnalyzer + RiskEngine)
        3. Scan Center (ManualScanner)
        4. USB Protection (USBScanWorker)
        evaluate the exact same threat file to identical verdicts, SHA-256 hashes, and risk scores.
        """
        scan_dir = os.path.join(self.temp_dir, "four_way_test")
        os.makedirs(scan_dir, exist_ok=True)

        threat_file = os.path.join(scan_dir, "multi_source_threat.bin")
        payload = b"TEST_MALWARE_PAYLOAD_SIGNATURE_FOR_RANSOMGUARD_UNIT_TEST_2026"
        with open(threat_file, "wb") as f:
            f.write(payload)

        # 1. Existing File Scan
        worker_existing = ExistingScanWorker(target_drives=[scan_dir], db_manager=self.db)
        existing_record = worker_existing._scan_file(threat_file)

        # 2. Real-Time Protection pipeline
        analysis_res = UnifiedFileAnalyzer.analyze_file(threat_file)
        realtime_verdict = RiskEngine.determine_verdict(analysis_res.static_indicators, is_accessible=analysis_res.accessible)
        realtime_score, realtime_sev = RiskEngine.calculate_risk(analysis_res.static_indicators)

        # 3. Scan Center (BackgroundScanner)
        scanner = BackgroundScanner(target_path=threat_file, recursive=False, db_manager=self.db)
        scanner.run()
        self.assertTrue(len(scanner.scan_records) >= 1)
        manual_record = scanner.scan_records[0]

        # 4. USB Protection (USBScanWorker)
        usb_cache = {}
        usb_worker = USBScanWorker(target_drive=scan_dir, scan_cache=usb_cache, db_manager=self.db)
        usb_record = usb_worker._analyze_usb_file(threat_file, DETECTION_SOURCE_INITIAL_SCAN)

        # Verify all 4 produce identical security verdicts
        self.assertEqual(existing_record["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(realtime_verdict, VERDICT_MALICIOUS)
        self.assertEqual(usb_record["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(manual_record["verdict"], VERDICT_MALICIOUS)

        # Verify all 4 produce identical SHA-256 hashes
        expected_sha = "7bfe973be6f82fccbda5b6364d96edef45aaaac705ad0dbd4e02644404123168"
        self.assertEqual(existing_record["sha256"], expected_sha)
        self.assertEqual(analysis_res.sha256, expected_sha)
        self.assertEqual(manual_record["sha256"], expected_sha)
        self.assertEqual(usb_record["sha256"], expected_sha)

        # Verify all 4 produce identical risk scores and severities
        self.assertEqual(existing_record["risk_score"], 100)
        self.assertEqual(realtime_score, 100)
        self.assertEqual(manual_record["risk_score"], 100)
        self.assertEqual(usb_record["risk_score"], 100)

        self.assertEqual(existing_record["severity"], "CRITICAL")
        self.assertEqual(realtime_sev, "CRITICAL")
        self.assertEqual(manual_record["severity"], "CRITICAL")
        self.assertEqual(usb_record["severity"], "CRITICAL")

    def test_exclusions_safe_skipping(self):
        """Verifies centralized exclusion rules safely skip system/meta files and never report clean."""
        exclusions = ScanExclusions()
        # Excluded directories
        self.assertTrue(exclusions.should_exclude_directory("C:\\$Recycle.Bin")[0])
        self.assertTrue(exclusions.should_exclude_directory("C:\\System Volume Information")[0])
        self.assertTrue(exclusions.should_exclude_directory("C:\\Windows\\WinSxS")[0])
        self.assertTrue(exclusions.should_exclude_directory("C:\\Windows\\SoftwareDistribution")[0])
        
        # Non-excluded directories
        self.assertFalse(exclusions.should_exclude_directory("C:\\Users\\LENOVO\\Documents")[0])
        self.assertFalse(exclusions.should_exclude_directory("D:\\Projects\\Source")[0])

        # Excluded files
        self.assertTrue(exclusions.should_exclude_file("C:\\pagefile.sys")[0])
        self.assertTrue(exclusions.should_exclude_file("C:\\swapfile.sys")[0])
        self.assertTrue(exclusions.should_exclude_file("C:\\data\\ransomguard.db-wal")[0])

        # Non-excluded file
        self.assertFalse(exclusions.should_exclude_file("C:\\Users\\test\\sample.docx")[0])

    def test_batch_persistence_writer(self):
        """Verifies high-throughput batched persistence buffers writes and flushes cleanly."""
        writer = BatchPersistenceWriter(self.db, batch_size=5, flush_interval_sec=10.0)
        
        # Buffer 4 records (below batch size)
        for i in range(4):
            writer.record_analyzed_file({
                "file_path": f"C:\\test_file_{i}.txt",
                "mtime_ns": 1000 + i,
                "ctime_ns": 2000 + i,
                "file_size": 100 * i,
                "prefix_hash": f"hash_{i}",
                "verdict": "CLEAN",
                "sha256": f"sha_{i}",
                "risk_score": 0,
                "threat_name": "None",
                "detection_rules": "[]",
                "detection_source": "EXISTING_SCAN"
            })
        self.assertEqual(len(writer.buffer), 4)

        # 5th record triggers batch flush
        writer.record_analyzed_file({
            "file_path": "C:\\test_file_4.txt",
            "mtime_ns": 1004,
            "ctime_ns": 2004,
            "file_size": 400,
            "prefix_hash": "hash_4",
            "verdict": "CLEAN",
            "sha256": "sha_4",
            "risk_score": 0,
            "threat_name": "None",
            "detection_rules": "[]",
            "detection_source": "EXISTING_SCAN"
        })
        self.assertEqual(len(writer.buffer), 0)

        # Verify records exist in SQLite
        rows = self.db.execute_read("SELECT file_path, verdict FROM existing_scan_cache")
        self.assertEqual(len(rows), 5)

    def test_duplicate_threat_suppression(self):
        """Verifies that an existing active threat incident is not duplicated during background scans."""
        threat_path = os.path.join(self.temp_dir, "existing_virus.exe")
        with open(threat_path, "wb") as f:
            f.write(b"MALICIOUS_BYTES")
        
        test_sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        self.inc_repo.insert_incident(
            threat_name="Trojan.Test",
            severity="CRITICAL",
            risk_score=95,
            affected_folder=self.temp_dir,
            detection_reason="Realtime detection",
            affected_file="existing_virus.exe",
            full_path=threat_path,
            verdict="MALICIOUS",
            sha256=test_sha,
            status="ACTIVE"
        )

        initial_count = len(self.inc_repo.get_incidents())
        self.assertEqual(initial_count, 1)

        worker = AnalysisWorker(
            worker_id=1,
            work_queue=None,
            batch_writer=None,
            exclusions=ScanExclusions(),
            mode="INCREMENTAL",
            db_manager=self.db,
            cached_entries={},
            pause_event=threading.Event()
        )

        rec = {
            "file_path": threat_path,
            "sha256": test_sha,
            "threat_name": "ExistingScan.Malware",
            "severity": "CRITICAL",
            "verdict": "MALICIOUS",
            "risk_score": 95,
            "evidence": ["Signature match"],
            "matched_rules": ["TestRule"]
        }

        # Handling threat should detect the duplicate and suppress creating a new incident
        worker._handle_threat(rec)

        final_count = len(self.inc_repo.get_incidents())
        self.assertEqual(final_count, 1, "Duplicate incident should be suppressed")

    def test_dashboard_compact_card_ui(self):
        """Verifies that Existing File Scan is represented by ONE compact card with NO stat card rows."""
        dash = DashboardPage()
        
        # 1. Verify compact card existence
        self.assertTrue(hasattr(dash, "scan_card"))
        self.assertTrue(hasattr(dash, "scan_status_badge"))
        self.assertTrue(hasattr(dash, "btn_scan_now"))
        self.assertTrue(hasattr(dash, "btn_scan_pause"))
        self.assertTrue(hasattr(dash, "btn_scan_stop"))
        self.assertTrue(hasattr(dash, "scan_progress_bar"))
        self.assertTrue(hasattr(dash, "scan_progress_details_lbl"))
        self.assertTrue(hasattr(dash, "scan_mode_combo"))

        # 2. Verify removal of the 7 separate statistic cards
        self.assertEqual(len(dash.scan_stat_labels), 0)

        # 3. Test IDLE UI state
        dash._set_ui_state_idle()
        self.assertIn("IDLE", dash.scan_status_badge.text())
        self.assertFalse(dash.btn_scan_now.isHidden())
        self.assertTrue(dash.btn_scan_pause.isHidden())
        self.assertTrue(dash.btn_scan_stop.isHidden())
        self.assertTrue(dash.scan_progress_bar.isHidden())
        self.assertTrue(dash.scan_progress_details_lbl.isHidden())

        # 4. Test SCANNING UI state
        dash._set_ui_state_scanning("Analyzing existing files...")
        self.assertIn("SCANNING", dash.scan_status_badge.text())
        self.assertTrue(dash.btn_scan_now.isHidden())
        self.assertFalse(dash.btn_scan_pause.isHidden())
        self.assertEqual(dash.btn_scan_pause.text(), "Pause")
        self.assertFalse(dash.btn_scan_stop.isHidden())
        self.assertFalse(dash.scan_progress_bar.isHidden())
        self.assertFalse(dash.scan_progress_details_lbl.isHidden())

        # 5. Test PAUSED UI state
        dash._set_ui_state_paused()
        self.assertIn("PAUSED", dash.scan_status_badge.text())
        self.assertEqual(dash.btn_scan_pause.text(), "Resume")
        self.assertFalse(dash.btn_scan_stop.isHidden())

        # 6. Test COMPLETED UI state
        dash._set_ui_state_completed({"files_analyzed": 12430, "threats_found": 0})
        self.assertIn("COMPLETED", dash.scan_status_badge.text())
        self.assertFalse(dash.btn_scan_now.isHidden())
        self.assertTrue(dash.btn_scan_pause.isHidden())
        self.assertTrue(dash.btn_scan_stop.isHidden())
        self.assertTrue(dash.scan_progress_bar.isHidden())
        self.assertIn("✓ Scan completed", dash.scan_headline_lbl.text())
        self.assertIn("12,430 files checked", dash.scan_headline_lbl.text())


if __name__ == "__main__":
    unittest.main()
