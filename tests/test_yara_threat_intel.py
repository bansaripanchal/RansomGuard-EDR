import os
import sys
import unittest
import tempfile
import shutil

from core.database.database import DatabaseManager
from core.analysis.yara_engine import YaraRuleEngine, YaraAnalysisResult, YaraMatch
from core.analysis.threat_intel_service import ThreatIntelligenceService, ThreatIntelResult
from core.analysis.file_analyzer import UnifiedFileAnalyzer
from core.detection.risk_engine import RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS


class TestYaraAndThreatIntel(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_yara_intel.db")
        self.db = DatabaseManager(self.db_path)
        self.db.init_db()

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def test_01_yara_no_matching_rule(self):
        """Test 1: File with no matching YARA rule returns No Match."""
        clean_file = os.path.join(self.temp_dir, "clean_file.txt")
        with open(clean_file, "w") as f:
            f.write("This is a benign text document with zero malware indicators.")

        res = YaraRuleEngine.scan_file(clean_file)
        self.assertEqual(res.status, "No Match")
        self.assertEqual(len(res.matches), 0)
        self.assertIn("No YARA rules matched", res.details)

    def test_02_yara_genuine_eicar_match(self):
        """Test 2: File with genuine EICAR test string matches EICAR_Test_File rule."""
        eicar_file = os.path.join(self.temp_dir, "sample_eicar.txt")
        with open(eicar_file, "wb") as f:
            f.write(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")

        res = YaraRuleEngine.scan_file(eicar_file)
        self.assertEqual(res.status, "Matched")
        self.assertEqual(len(res.matches), 1)
        self.assertEqual(res.matches[0].rule_name, "EICAR_Test_File")
        self.assertIn("Matched EICAR test pattern", res.matches[0].evidence)

    def test_03_yara_multiple_rule_matches(self):
        """Test 3: File triggering multiple genuine YARA rules."""
        multi_file = os.path.join(self.temp_dir, "multi_test.ps1")
        with open(multi_file, "wb") as f:
            # Contains both PowerShell obfuscation strings and Ransomware note storm strings
            f.write(
                b"Invoke-Expression -WindowStyle Hidden\n"
                b"your files have been encrypted! how to decrypt files restore your files bitcoin tor browser"
            )

        res = YaraRuleEngine.scan_file(multi_file)
        self.assertEqual(res.status, "Matched")
        self.assertTrue(len(res.matches) >= 2)
        matched_names = [m.rule_name for m in res.matches]
        self.assertIn("Suspicious_PowerShell_Obfuscation", matched_names)
        self.assertIn("Ransomware_Note_Keyword_Storm", matched_names)

    def test_04_threat_intel_known_malicious(self):
        """Test 4: Threat Intelligence lookup for known malicious hash."""
        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        intel_service = ThreatIntelligenceService(self.db)
        res = intel_service.lookup_hash(eicar_hash)

        self.assertEqual(res.status, "Known Malicious")
        self.assertGreater(res.reputation_score, 50)
        self.assertIn("EICAR", res.malware_family)

    def test_05_threat_intel_unknown_hash(self):
        """Test 5: Unknown hash returns No Reputation Data (NOT clean)."""
        unknown_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        intel_service = ThreatIntelligenceService(self.db)
        res = intel_service.lookup_hash(unknown_hash)

        self.assertEqual(res.status, "No Reputation Data")
        self.assertNotEqual(res.status, "CLEAN")
        self.assertIn("No reputation data", res.details)

    def test_06_threat_intel_caching(self):
        """Test 6: SQLite cache saves and retrieves threat intelligence results."""
        hash_val = "ed97d377b8cf7527e52d95e347854659b8b371a02140612dc401d90f225f1025"
        intel_service = ThreatIntelligenceService(self.db)

        # 1st Lookup -> Populates Cache
        res1 = intel_service.lookup_hash(hash_val)
        self.assertEqual(res1.status, "Known Malicious")
        self.assertFalse(res1.is_cached)

        # 2nd Lookup -> Returns Cached Result
        res2 = intel_service.lookup_hash(hash_val)
        self.assertEqual(res2.status, "Known Malicious")
        self.assertTrue(res2.is_cached)

    def test_07_unified_analyzer_integration(self):
        """Test 7: UnifiedFileAnalyzer combines YARA + Threat Intel into evidence for RiskEngine."""
        eicar_file = os.path.join(self.temp_dir, "eicar_integrated.txt")
        with open(eicar_file, "wb") as f:
            f.write(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")

        analysis_res = UnifiedFileAnalyzer.analyze_file(eicar_file)

        self.assertEqual(analysis_res.yara_status, "Matched")
        self.assertEqual(analysis_res.reputation_status, "Known Malicious")

        # Evaluate through RiskEngine
        risk_eval = RiskEngine.evaluate_evidence({
            "static_indicators": analysis_res.static_indicators,
            "is_known_hash": True,
            "is_accessible": True,
            "has_errors": False
        })

        self.assertIn(risk_eval["severity"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(risk_eval["risk_score"], 80)

    def test_08_invalid_file_graceful_handling(self):
        """Test 8: Invalid file handling without exception or crash."""
        invalid_path = os.path.join(self.temp_dir, "non_existent_file.bin")
        res_yara = YaraRuleEngine.scan_file(invalid_path)
        self.assertEqual(res_yara.status, "Error")

        res_analysis = UnifiedFileAnalyzer.analyze_file(invalid_path)
        self.assertIsNotNone(res_analysis.error)


if __name__ == "__main__":
    unittest.main()
