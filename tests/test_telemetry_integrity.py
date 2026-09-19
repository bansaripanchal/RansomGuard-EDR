import os
import sys
import time
import tempfile
import unittest
import psutil

from core.database.database import DatabaseManager
from core.database.events_repository import EventsRepository
from core.database.incidents_repository import IncidentsRepository
from core.monitoring.process_monitor import ProcessMonitor
from core.monitoring.event_handler import FileSystemEventHandlerImpl
from core.monitoring.event_queue import EventQueue
from core.detection.behavior_engine import BehaviorEngine
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from ui.components.tables import format_file_size

class TestTelemetryIntegrity(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, 'conn'):
            self.db._local.conn = None
        self.db.init_db()

        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)
        self.proc_mon = ProcessMonitor()
        self.engine = BehaviorEngine(self.db, self.proc_mon)

    def tearDown(self):
        self.db.close_connection()
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
            if os.path.exists(self.db_path + '-wal'):
                os.remove(self.db_path + '-wal')
            if os.path.exists(self.db_path + '-shm'):
                os.remove(self.db_path + '-shm')
        except PermissionError:
            pass

    def test_01_normal_pdf_modify(self):
        events = [('MODIFY', 'C:/Users/User/Documents/report.pdf', None, '.pdf', 1048576, None)]
        incidents = self.engine.process_new_events(events)
        self.assertEqual(len(incidents), 0)

        evidence = {
            'created_count': 0, 'modified_count': 1, 'renamed_count': 0, 'deleted_count': 0,
            'duration_sec': 5.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['verdict'], VERDICT_CLEAN)

    def test_02_normal_xlsx_modify(self):
        events = [('MODIFY', 'C:/Finance/Q3_Spreadsheet.xlsx', None, '.xlsx', 524288, None)]
        incidents = self.engine.process_new_events(events)
        self.assertEqual(len(incidents), 0)

        evidence = {
            'created_count': 0, 'modified_count': 1, 'renamed_count': 0, 'deleted_count': 0,
            'duration_sec': 5.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['verdict'], VERDICT_CLEAN)

    def test_03_single_rename(self):
        events = [('RENAME', 'C:/Projects/draft.docx', 'C:/Projects/final.docx', '.docx', 25000, None)]
        incidents = self.engine.process_new_events(events)
        self.assertEqual(len(incidents), 0)

        evidence = {
            'created_count': 0, 'modified_count': 0, 'renamed_count': 1, 'deleted_count': 0,
            'duration_sec': 5.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['verdict'], VERDICT_CLEAN)

    def test_04_single_delete(self):
        events = [('DELETE', 'C:/Temp/scratch.tmp', None, '.tmp', 1024, None)]
        incidents = self.engine.process_new_events(events)
        self.assertEqual(len(incidents), 0)

        evidence = {
            'created_count': 0, 'modified_count': 0, 'renamed_count': 0, 'deleted_count': 1,
            'duration_sec': 5.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['verdict'], VERDICT_CLEAN)

    def test_05_rapid_rename_burst(self):
        evidence = {
            'created_count': 0, 'modified_count': 0, 'renamed_count': 25, 'deleted_count': 0,
            'duration_sec': 2.0, 'extension_changes': 25, 'suspicious_extensions_count': 25,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertGreaterEqual(res['risk_score'], 60)
        self.assertIn(res['severity'], ('HIGH', 'CRITICAL'))

    def test_06_mass_modification_burst(self):
        evidence = {
            'created_count': 0, 'modified_count': 55, 'renamed_count': 0, 'deleted_count': 0,
            'duration_sec': 4.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertGreaterEqual(res['risk_score'], 35)
        self.assertIn(res['severity'], ('MEDIUM', 'HIGH', 'CRITICAL'))

    def test_07_canary_tampering(self):
        events = [
            ('MODIFY', 'E:/RansomGuard_Test/RG_Simulator/!000_canary_decoy.docx', None, '.docx', 1024, None),
            ('DELETE', 'E:/RansomGuard_Test/RG_Simulator/_canary_honeypot.xlsx', None, '.xlsx', 2048, None),
            ('MODIFY', 'E:/RansomGuard_Test/RG_Simulator/data1.txt', None, '.txt', 1024, None),
            ('MODIFY', 'E:/RansomGuard_Test/RG_Simulator/data2.txt', None, '.txt', 1024, None),
            ('MODIFY', 'E:/RansomGuard_Test/RG_Simulator/data3.txt', None, '.txt', 1024, None),
        ]
        incidents = self.engine.process_new_events(events)
        self.assertGreaterEqual(len(incidents), 1)
        inc_data = incidents[0][0]
        self.assertIn(inc_data['severity'], ('HIGH', 'CRITICAL'))
        self.assertEqual(inc_data['verdict'], VERDICT_MALICIOUS)
        self.assertIn('Canary', inc_data['threat_name'])

    def test_08_ransom_note_creation(self):
        evidence = {
            'created_count': 1, 'modified_count': 0, 'renamed_count': 0, 'deleted_count': 0,
            'duration_sec': 5.0, 'extension_changes': 0, 'suspicious_extensions_count': 0,
            'canary_events': [], 'ransom_notes': ['HOW_TO_RECOVER_FILES.txt'],
            'static_indicators': [], 'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res = RiskEngine.evaluate_evidence(evidence)
        self.assertEqual(res['risk_score'], 30)
        self.assertEqual(res['verdict'], VERDICT_SUSPICIOUS)

    def test_09_long_windows_path(self):
        long_dir = 'C:/Corporate_Data/Departments/Enterprise_Risk_Management/Audits/2026/Quarterly_Reports/Compliance_Documentation'
        long_path = f'{long_dir}/Internal_Control_Evaluation_Confidential_Assessment_Master_File.xlsx'
        norm_expected = os.path.normpath(os.path.abspath(long_path))

        self.events_repo.insert_event('CREATE', norm_expected, None, '.xlsx', 45000)
        events = self.events_repo.get_events(limit=10)
        self.assertTrue(len(events) > 0)
        self.assertEqual(events[0]['src_path'], norm_expected)
        self.assertNotIn('...', events[0]['src_path'])

    def test_10_deleted_file_size_handling(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'RansomGuard File Size Telemetry Persistence Test')
            temp_path = f.name

        q = EventQueue()
        handler = FileSystemEventHandlerImpl(q, self.proc_mon)
        
        # Simulate create event
        handler._enqueue_event('CREATE', temp_path)
        batch = q.get_batch()
        self.assertTrue(len(batch) > 0)
        c_size = batch[0][4]
        self.assertEqual(c_size, 48)
        self.assertEqual(format_file_size(c_size), '0.01 MB')

        # Delete file from disk
        os.remove(temp_path)

        # Handle delete
        handler._enqueue_event('DELETE', temp_path)
        del_batch = q.get_batch()
        self.assertTrue(len(del_batch) > 0)
        d_size = del_batch[0][4]
        self.assertEqual(d_size, 48)
        self.assertEqual(format_file_size(d_size), '0.01 MB')

        # Ghost delete
        handler._enqueue_event('DELETE', 'C:/non_existent_before.bin')
        ghost_batch = q.get_batch()
        self.assertTrue(len(ghost_batch) > 0)
        ghost_size = ghost_batch[0][4]
        self.assertEqual(ghost_size, -1)
        self.assertEqual(format_file_size(ghost_size), 'Deleted before capture')
        self.assertEqual(format_file_size(None), 'Unavailable')
        self.assertEqual(format_file_size(-2), 'Unavailable')

    def test_11_process_attribution_available(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'Process correlation test')
            temp_file = f.name

        try:
            with open(temp_file, 'rb') as active_handle:
                match = self.proc_mon.find_process_accessing_path(temp_file)
                self.assertIsNotNone(match)
                proc_name = match['name']
                pid = match['pid']
                status = match['attribution_status']
                self.assertTrue(bool(proc_name))
                self.assertIsInstance(pid, int)
                self.assertGreater(pid, 0)
                self.assertIn(status, ('DIRECT', 'CORRELATED'))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_12_process_attribution_unavailable(self):
        match = self.proc_mon.find_process_accessing_path('C:/Totally_Fictional_Path_99999.xyz')
        self.assertIsNone(match)

        events = [('MODIFY', 'C:/test/canary.docx', None, '.docx', 1024, None)]
        incidents = self.engine.process_new_events(events)
        if incidents:
            inc_data = incidents[0][0]
            self.assertEqual(inc_data['process_name'], 'Unknown')
            self.assertIsNone(inc_data['process_pid'])
            self.assertEqual(inc_data['attribution_status'], 'UNAVAILABLE')

    def test_13_deterministic_risk_calculation(self):
        evidence_scenario = {
            'created_count': 5, 'modified_count': 30, 'renamed_count': 12, 'deleted_count': 2,
            'duration_sec': 4.5, 'extension_changes': 10, 'suspicious_extensions_count': 8,
            'canary_events': [], 'ransom_notes': [], 'static_indicators': [],
            'is_known_hash': False, 'is_accessible': True, 'has_errors': False
        }
        res1 = RiskEngine.evaluate_evidence(evidence_scenario)
        res2 = RiskEngine.evaluate_evidence(evidence_scenario)

        self.assertEqual(res1['risk_score'], res2['risk_score'])
        self.assertEqual(res1['severity'], res2['severity'])
        self.assertEqual(res1['verdict'], res2['verdict'])
        self.assertEqual(res1['evidence_lines'], res2['evidence_lines'])
        self.assertEqual(res1['primary_threat_name'], res2['primary_threat_name'])
        self.assertGreater(res1['risk_score'], 0)

    def test_14_incident_resolution_lifecycle(self):
        # 1. Create active incident
        inc1_id = self.inc_repo.insert_incident(
            threat_name="Ransomware Rapid Mutation",
            severity="HIGH",
            risk_score=80,
            affected_folder="C:/UserData",
            detection_reason="Rapid extension changes",
            status="ACTIVE"
        )
        dash_alerts = self.inc_repo.get_incidents(status_filter="ACTIVE", limit=6)
        active_count = self.inc_repo.get_active_incidents_count()
        threat_repo_all = self.inc_repo.get_incidents()
        self.assertEqual(len(dash_alerts), 1)
        self.assertEqual(active_count, 1)
        self.assertEqual(threat_repo_all[0]["status"], "ACTIVE")

        # 2. Resolve incident
        self.inc_repo.resolve_incident(inc1_id)
        dash_alerts = self.inc_repo.get_incidents(status_filter="ACTIVE", limit=6)
        active_count = self.inc_repo.get_active_incidents_count()
        threat_repo_all = self.inc_repo.get_incidents()
        threat_repo_resolved = self.inc_repo.get_incidents(status_filter="RESOLVED")
        self.assertEqual(len(dash_alerts), 0)
        self.assertEqual(active_count, 0)
        self.assertEqual(threat_repo_all[0]["status"], "RESOLVED")
        self.assertEqual(len(threat_repo_resolved), 1)

        # 3. Create second active incident
        inc2_id = self.inc_repo.insert_incident(
            threat_name="Extortion Note Detected",
            severity="CRITICAL",
            risk_score=95,
            affected_folder="C:/UserData",
            detection_reason="Canary honeypot touched",
            status="ACTIVE"
        )
        dash_alerts = self.inc_repo.get_incidents(status_filter="ACTIVE", limit=6)
        active_count = self.inc_repo.get_active_incidents_count()
        threat_repo_all = self.inc_repo.get_incidents()
        self.assertEqual(len(dash_alerts), 1)
        self.assertEqual(dash_alerts[0]["id"], inc2_id)
        self.assertEqual(active_count, 1)
        self.assertEqual(len(threat_repo_all), 2)

        # 4. Resolve second incident
        self.inc_repo.resolve_incident(inc2_id)
        dash_alerts = self.inc_repo.get_incidents(status_filter="ACTIVE", limit=6)
        active_count = self.inc_repo.get_active_incidents_count()
        threat_repo_all = self.inc_repo.get_incidents()
        self.assertEqual(len(dash_alerts), 0)
        self.assertEqual(active_count, 0)
        self.assertEqual(len(threat_repo_all), 2)
        self.assertTrue(all(r["status"] == "RESOLVED" for r in threat_repo_all))

if __name__ == '__main__':
    unittest.main()