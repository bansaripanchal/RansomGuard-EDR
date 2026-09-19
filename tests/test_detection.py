import unittest
import time
from core.detection.rules import DetectionRules
from core.detection.risk_engine import RiskEngine

class TestDetectionEngine(unittest.TestCase):
    def test_risk_scoring_low(self):
        # Empty rules
        score, severity = RiskEngine.calculate_risk([])
        self.assertEqual(score, 0)
        self.assertEqual(severity, "LOW")

    def test_risk_scoring_medium(self):
        # Mass creation rule alone is ordinary activity
        rules = [{"rule_name": "MASS_FILE_CREATION"}]
        score, severity = RiskEngine.calculate_risk(rules)
        self.assertEqual(score, 0)
        self.assertEqual(severity, "LOW")

        # Mass modification rule produces evidence-derived score
        rules = [{"rule_name": "MASS_FILE_MODIFICATION"}]
        score, severity = RiskEngine.calculate_risk(rules)
        self.assertEqual(score, 35)
        self.assertEqual(severity, "MEDIUM")

    def test_risk_scoring_critical_combined(self):
        # Triggering multiple indicators
        rules = [
            {"rule_name": "MASS_FILE_RENAME"},
            {"rule_name": "MASS_FILE_MODIFICATION"},
            {"rule_name": "SUSPICIOUS_EXTENSION"},
            {"rule_name": "COMBINED_RANSOMWARE_BEHAVIOR"}
        ]
        score, severity = RiskEngine.calculate_risk(rules)
        self.assertGreaterEqual(score, 75)
        self.assertEqual(severity, "CRITICAL")

    def test_rules_evaluation_normal(self):
        # A few sporadic modifications (normal activity)
        events = [
            (time.time(), "MODIFY", "C:\\data\\doc1.txt", None, ".txt", 1024),
            (time.time(), "MODIFY", "C:\\data\\doc2.txt", None, ".txt", 2048),
            (time.time(), "CREATE", "C:\\data\\doc3.txt", None, ".txt", 0)
        ]
        triggered = DetectionRules.evaluate_directory_activity(events, duration_sec=5.0)
        self.assertEqual(len(triggered), 0) # No rules triggered!

    def test_rules_evaluation_mass_rename(self):
        # Simulate 25 file renames to suspicious extensions
        events = []
        for i in range(25):
            events.append((
                time.time(), "RENAME", f"C:\\data\\file{i}.txt", f"C:\\data\\file{i}.locked", ".locked", 2048
            ))
            events.append((
                time.time(), "MODIFY", f"C:\\data\\file{i}.txt", None, ".txt", 2048
            ))
            
        triggered = DetectionRules.evaluate_directory_activity(events, duration_sec=5.0)
        rule_names = [r["rule_name"] for r in triggered]
        
        self.assertTrue("MASS_FILE_RENAME" in rule_names)
        self.assertTrue("SUSPICIOUS_EXTENSION" in rule_names)
        self.assertTrue("COMBINED_RANSOMWARE_BEHAVIOR" in rule_names)

    def test_rules_ransom_note(self):
        events = [
            (time.time(), "CREATE", "C:\\data\\README_FOR_DECRYPT.txt", None, ".txt", 512)
        ]
        triggered = DetectionRules.evaluate_directory_activity(events, duration_sec=5.0)
        rule_names = [r["rule_name"] for r in triggered]
        self.assertTrue("RANSOM_NOTE_CREATION" in rule_names)
        
        # Risk score calculation is evidence-derived (single note = 30 points, SUSPICIOUS)
        score, severity = RiskEngine.calculate_risk(triggered)
        self.assertEqual(score, 30)
        self.assertEqual(severity, "LOW")

    def test_canary_tampering_detection(self):
        from core.detection.behavior_engine import BehaviorEngine
        from core.database.database import DatabaseManager
        
        # Test directory activity rule evaluation
        events = [
            (time.time(), "MODIFY", "E:\\RansomGuard_Test\\RG_Simulator\\!000_canary_decoy.docx", None, ".docx", 1024),
            (time.time(), "DELETE", "E:\\RansomGuard_Test\\RG_Simulator\\_canary_honeypot.xlsx", None, ".xlsx", 2048)
        ]
        triggered = DetectionRules.evaluate_directory_activity(events, duration_sec=5.0)
        rule_names = [r["rule_name"] for r in triggered]
        self.assertTrue("CANARY_FILE_TAMPERING" in rule_names)
        
        # Multiple canaries evaluated via evidence produces 55 points, MEDIUM severity
        score, severity = RiskEngine.calculate_risk(triggered)
        self.assertEqual(score, 55)
        self.assertEqual(severity, "MEDIUM")
        
        # Test individual file analysis
        db = DatabaseManager(":memory:")
        db.init_db()
        engine = BehaviorEngine(db, process_monitor=None)
        threat = engine._analyze_file_for_threat("MODIFY", "E:\\test\\!0_SYSTEM_CANARY.txt", None, ".txt", 512)
        self.assertIsNotNone(threat)
        self.assertEqual(threat["rule_name"], "CANARY_FILE_TAMPERING")
        self.assertEqual(threat["threat_name"], "Canary / Tripwire File Tampering")

    def test_zero_fake_process_attribution(self):
        from core.detection.behavior_engine import BehaviorEngine
        from core.database.database import DatabaseManager
        
        db = DatabaseManager(":memory:")
        db.init_db()
        engine = BehaviorEngine(db, process_monitor=None)
        
        # Test canary tamper event produces an incident with Unknown attribution
        events = [("MODIFY", "E:\\test\\!0_SYSTEM_CANARY.txt", None, ".txt", 1024, None)]
        incidents = engine.process_new_events(events)
        self.assertEqual(len(incidents), 1)
        inc_data = incidents[0][0]
        self.assertEqual(inc_data["process_name"], "Unknown")
        self.assertEqual(inc_data["attribution_status"], "UNAVAILABLE")
        self.assertIsNone(inc_data["process_pid"])

if __name__ == "__main__":
    unittest.main()
