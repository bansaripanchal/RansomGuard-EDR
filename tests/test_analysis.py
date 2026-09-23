import os
import sys
import tempfile
import unittest
import hashlib
from core.analysis.file_analyzer import UnifiedFileAnalyzer, calculate_shannon_entropy
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from core.detection.behavior_engine import BehaviorEngine
from core.database.database import DatabaseManager

class TestUnifiedAnalysisPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="rg_test_analysis_")

    def tearDown(self):
        import shutil
        try:
            shutil.rmtree(self.test_dir, ignore_errors=True)
        except Exception:
            pass

    def test_1_clean_ordinary_file(self):
        """Clean ordinary document should produce CLEAN verdict with genuine evidence."""
        clean_file = os.path.join(self.test_dir, "annual_report.txt")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("Annual financial review: Q3 revenue was within expected bounds.")

        res = UnifiedFileAnalyzer.analyze_file(clean_file)
        self.assertTrue(res.accessible)
        self.assertEqual(res.detected_file_type, "Plain Text Document")
        self.assertIsNotNone(res.sha256)
        self.assertIsNotNone(res.md5)
        self.assertEqual(len(res.static_indicators), 0)

        # Explicit capability reporting
        self.assertIn(res.yara_status, ["No Match", "NOT_CONFIGURED"])
        self.assertIn(res.reputation_status, ["No Reputation Data", "NOT_AVAILABLE"])

        verdict = RiskEngine.determine_verdict(res.static_indicators, is_accessible=res.accessible)
        score, severity = RiskEngine.calculate_risk(res.static_indicators)
        self.assertEqual(verdict, VERDICT_CLEAN)
        self.assertEqual(score, 0)
        self.assertEqual(severity, "LOW")

    def test_2_suspicious_script_heuristics(self):
        """Single weak script heuristic (score 15) must remain CLEAN (informational finding)."""
        script_file = os.path.join(self.test_dir, "suspicious_task.ps1")
        with open(script_file, "w", encoding="utf-8") as f:
            f.write("# Suspicious payload script\nwscript.shell invoke-expression iex -w hidden bypass")

        res = UnifiedFileAnalyzer.analyze_file(script_file)
        self.assertTrue(res.accessible)
        self.assertEqual(res.detected_file_type, "PowerShell Script")
        
        # Indicator check
        rule_names = [i["rule_name"] for i in res.static_indicators]
        self.assertIn("SUSPICIOUS_SCRIPT_HEURISTICS", rule_names)

        verdict = RiskEngine.determine_verdict(res.static_indicators, is_accessible=res.accessible)
        score, severity = RiskEngine.calculate_risk(res.static_indicators)
        # Single weak indicator (score 15) must not automatically become SUSPICIOUS
        self.assertEqual(verdict, VERDICT_CLEAN)
        self.assertEqual(score, 15)
        self.assertEqual(severity, "LOW")

    def test_3_known_malware_hash_signature(self):
        """Known malicious SHA-256 signature match must produce MALICIOUS."""
        malware_sample = os.path.join(self.test_dir, "test_malware_sample.bin")
        payload = b"TEST_MALWARE_PAYLOAD_SIGNATURE_FOR_RANSOMGUARD_UNIT_TEST_2026"
        with open(malware_sample, "wb") as f:
            f.write(payload)

        res = UnifiedFileAnalyzer.analyze_file(malware_sample)
        self.assertTrue(res.accessible)
        self.assertEqual(res.sha256, "7bfe973be6f82fccbda5b6364d96edef45aaaac705ad0dbd4e02644404123168")
        
        rule_names = [i["rule_name"] for i in res.static_indicators]
        self.assertIn("KNOWN_MALWARE_HASH_MATCH", rule_names)

        verdict = RiskEngine.determine_verdict(res.static_indicators, is_accessible=res.accessible)
        score, severity = RiskEngine.calculate_risk(res.static_indicators)
        self.assertEqual(verdict, VERDICT_MALICIOUS)
        self.assertEqual(score, 100)
        self.assertEqual(severity, "CRITICAL")

    def test_4_real_pe_file_inspection(self):
        """Real Windows executable (python.exe) must be authentically parsed using pefile."""
        py_exe = sys.executable
        self.assertTrue(os.path.exists(py_exe))

        res = UnifiedFileAnalyzer.analyze_file(py_exe)
        self.assertTrue(res.accessible)
        self.assertEqual(res.detected_file_type, "Windows Portable Executable (PE32/PE64)")
        self.assertIsNotNone(res.pe_info)
        self.assertTrue(res.pe_info.get("is_pe"))
        self.assertGreater(res.pe_info.get("number_of_sections", 0), 0)
        self.assertGreater(res.pe_info.get("max_section_entropy", 0), 0.0)
        self.assertIn(res.pe_info.get("subsystem"), ("WINDOWS_CUI (Console)", "WINDOWS_GUI"))

    def test_5_cryptographic_hashing_correctness(self):
        """Verifies SHA-256 and MD5 computed from actual file bytes match mathematical ground truth."""
        test_file = os.path.join(self.test_dir, "hash_test.bin")
        sample_bytes = b"RansomGuard EDR Ground Truth Evidence 2026"
        with open(test_file, "wb") as f:
            f.write(sample_bytes)

        expected_sha256 = hashlib.sha256(sample_bytes).hexdigest().lower()
        expected_md5 = hashlib.md5(sample_bytes).hexdigest().lower()

        res = UnifiedFileAnalyzer.analyze_file(test_file)
        self.assertEqual(res.sha256, expected_sha256)
        self.assertEqual(res.md5, expected_md5)

    def test_6_inaccessible_and_missing_files(self):
        """Missing or inaccessible file must report UNKNOWN / UNABLE TO DETERMINE without crashing."""
        ghost_path = os.path.join(self.test_dir, "does_not_exist.bin")
        res = UnifiedFileAnalyzer.analyze_file(ghost_path)
        self.assertFalse(res.accessible)
        self.assertIsNotNone(res.error)

        verdict = RiskEngine.determine_verdict(res.static_indicators, is_accessible=res.accessible, has_errors=bool(res.error))
        self.assertEqual(verdict, VERDICT_UNKNOWN)

    def test_7_weak_indicators_not_automatically_suspicious(self):
        """Single weak indicator (score < 50) must remain CLEAN (informational finding)."""
        # 1. Suspicious extension alone (score 15)
        locked_file = os.path.join(self.test_dir, "document.locked")
        with open(locked_file, "wb") as f:
            f.write(b"Single isolated locked file without mass rename behavior")

        res_locked = UnifiedFileAnalyzer.analyze_file(locked_file)
        verdict_locked = RiskEngine.determine_verdict(res_locked.static_indicators, is_accessible=res_locked.accessible)
        self.assertEqual(verdict_locked, VERDICT_CLEAN)
        self.assertNotEqual(verdict_locked, VERDICT_SUSPICIOUS)
        self.assertNotEqual(verdict_locked, VERDICT_MALICIOUS)

        # 2. Ransom note pattern alone (score 30)
        note_file = os.path.join(self.test_dir, "README_RECOVER.txt")
        with open(note_file, "w") as f:
            f.write("Single test note")

        res_note = UnifiedFileAnalyzer.analyze_file(note_file)
        verdict_note = RiskEngine.determine_verdict(res_note.static_indicators, is_accessible=res_note.accessible)
        self.assertEqual(verdict_note, VERDICT_CLEAN)
        self.assertNotEqual(verdict_note, VERDICT_SUSPICIOUS)

        # 3. Accumulated indicators reaching threshold (score >= 50) -> SUSPICIOUS
        multi_indicators = [
            {"rule_name": "RANSOM_NOTE_PATTERN", "reason": "Filename matches ransom note"}, # +30
            {"rule_name": "SUSPICIOUS_PE_CHARACTERISTICS", "reason": "Packed section"}      # +20
        ]
        verdict_multi = RiskEngine.determine_verdict(multi_indicators)
        self.assertEqual(verdict_multi, VERDICT_SUSPICIOUS)

    def test_8_normal_activity_does_not_create_malware_alert(self):
        """Creating or modifying a single normal file in live monitoring must NOT create an incident."""
        db = DatabaseManager(":memory:")
        db.init_db()
        engine = BehaviorEngine(db, process_monitor=None)

        # Single normal PDF create
        normal_events = [("CREATE", "C:\\data\\invoice.pdf", None, ".pdf", 2048, None)]
        incidents = engine.process_new_events(normal_events)
        self.assertEqual(len(incidents), 0)

        # Single normal document modify
        normal_modify = [("MODIFY", "C:\\data\\invoice.pdf", None, ".pdf", 4096, None)]
        incidents = engine.process_new_events(normal_modify)
        self.assertEqual(len(incidents), 0)

    def test_9_shannon_entropy_calculation(self):
        """Calculates Shannon entropy accurately across uniform and randomized byte streams."""
        # Zero entropy for identical bytes
        all_zeros = b"\x00" * 1000
        self.assertEqual(calculate_shannon_entropy(all_zeros), 0.0)

        # High entropy for uniform distribution across 256 bytes
        all_bytes = bytes(range(256)) * 10
        self.assertGreater(calculate_shannon_entropy(all_bytes), 7.9)

if __name__ == "__main__":
    unittest.main()
