import unittest
import os
import tempfile
import sqlite3
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository
from ui.pages.threats_page import ThreatsPage

# Ensure QApplication exists for UI tests
app = QApplication.instance()
if not app:
    app = QApplication([])


class TestThreatDismissal(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None
        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)

    def tearDown(self):
        self.db.close_connection()
        os.close(self.db_fd)
        try:
            os.remove(self.db_path)
            if os.path.exists(self.db_path + "-wal"):
                os.remove(self.db_path + "-wal")
            if os.path.exists(self.db_path + "-shm"):
                os.remove(self.db_path + "-shm")
        except (PermissionError, FileNotFoundError):
            pass

    def test_01_dismiss_incident_persisted_across_restarts(self):
        """Confirm that dismissing an incident persists in the DB and remains dismissed after re-opening."""
        inc_id = self.inc_repo.insert_incident(
            threat_name="Potential Ransom Note Pattern",
            severity="LOW",
            risk_score=30,
            affected_folder="C:\\test",
            affected_file="README.md",
            detection_reason="Pattern match",
            status="ACTIVE"
        )
        # Visible initially
        visible_before = self.inc_repo.get_incidents()
        self.assertEqual(len(visible_before), 1)
        self.assertEqual(visible_before[0]["id"], inc_id)
        self.assertFalse(self.inc_repo.is_incident_dismissed(inc_id))

        # Dismiss
        self.inc_repo.dismiss_incident(inc_id)
        self.assertTrue(self.inc_repo.is_incident_dismissed(inc_id))

        # Excluded from default get_incidents()
        visible_after = self.inc_repo.get_incidents()
        self.assertEqual(len(visible_after), 0)

        # Included if include_dismissed=True
        all_incs = self.inc_repo.get_incidents(include_dismissed=True)
        self.assertEqual(len(all_incs), 1)
        self.assertEqual(all_incs[0]["id"], inc_id)

        # SIMULATE RESTART: close connection, instantiate fresh DatabaseManager on the same path
        self.db.close_connection()
        fresh_db = DatabaseManager(self.db_path)
        if hasattr(fresh_db._local, "conn"):
            fresh_db._local.conn = None
        fresh_repo = IncidentsRepository(fresh_db)

        # Must still be dismissed across restart
        self.assertTrue(fresh_repo.is_incident_dismissed(inc_id))
        self.assertEqual(len(fresh_repo.get_incidents()), 0)
        self.assertEqual(len(fresh_repo.get_incidents(include_dismissed=True)), 1)
        fresh_db.close_connection()

    def test_02_multiple_dismissals(self):
        """Test dismissing multiple threats: A, B, C dismissed; D remains visible across restart."""
        id_a = self.inc_repo.insert_incident("Threat A", "LOW", 30, "C:\\test", "Reason A")
        id_b = self.inc_repo.insert_incident("Threat B", "MEDIUM", 50, "C:\\test", "Reason B")
        id_c = self.inc_repo.insert_incident("Threat C", "HIGH", 80, "C:\\test", "Reason C")
        id_d = self.inc_repo.insert_incident("Threat D", "CRITICAL", 95, "C:\\test", "Reason D")

        self.assertEqual(len(self.inc_repo.get_incidents()), 4)

        # Dismiss A, B, C
        self.inc_repo.dismiss_incident(id_a)
        self.inc_repo.dismiss_incident(id_b)
        self.inc_repo.dismiss_incident(id_c)

        # Only D should be visible
        visible = self.inc_repo.get_incidents()
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["id"], id_d)

        # Simulate restart
        self.db.close_connection()
        fresh_db = DatabaseManager(self.db_path)
        if hasattr(fresh_db._local, "conn"):
            fresh_db._local.conn = None
        fresh_repo = IncidentsRepository(fresh_db)

        reopened_visible = fresh_repo.get_incidents()
        self.assertEqual(len(reopened_visible), 1)
        self.assertEqual(reopened_visible[0]["id"], id_d)
        self.assertTrue(fresh_repo.is_incident_dismissed(id_a))
        self.assertTrue(fresh_repo.is_incident_dismissed(id_b))
        self.assertTrue(fresh_repo.is_incident_dismissed(id_c))
        self.assertFalse(fresh_repo.is_incident_dismissed(id_d))
        fresh_db.close_connection()

    def test_03_exact_threat_identification(self):
        """Confirm dismissal targets the exact threat ID, not name/severity/target."""
        # Two threats with identical attributes
        id_1 = self.inc_repo.insert_incident(
            threat_name="Potential Ransom Note Pattern",
            severity="LOW",
            risk_score=30,
            affected_folder="C:\\folder",
            affected_file="README.md",
            detection_reason="Pattern match",
            status="ACTIVE"
        )
        id_2 = self.inc_repo.insert_incident(
            threat_name="Potential Ransom Note Pattern",
            severity="LOW",
            risk_score=30,
            affected_folder="C:\\folder",
            affected_file="README.md",
            detection_reason="Pattern match",
            status="ACTIVE"
        )
        self.assertNotEqual(id_1, id_2)
        self.assertEqual(len(self.inc_repo.get_incidents()), 2)

        # Dismiss ONLY id_1
        self.inc_repo.dismiss_incident(id_1)

        visible = self.inc_repo.get_incidents()
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["id"], id_2)
        self.assertTrue(self.inc_repo.is_incident_dismissed(id_1))
        self.assertFalse(self.inc_repo.is_incident_dismissed(id_2))

    def test_04_dismiss_does_not_resolve_and_resolve_does_not_dismiss(self):
        """Confirm DISMISS ≠ RESOLVE: dismissing keeps status ACTIVE, resolving keeps dismissed=0."""
        inc_id = self.inc_repo.insert_incident(
            threat_name="Mass Encryption",
            severity="HIGH",
            risk_score=85,
            affected_folder="C:\\data",
            detection_reason="Rapid modification",
            status="ACTIVE"
        )
        # Dismissing must NOT change status to RESOLVED
        self.inc_repo.dismiss_incident(inc_id)
        inc_data = self.inc_repo.get_incident(inc_id)
        self.assertEqual(inc_data["status"], "ACTIVE")
        self.assertEqual(inc_data["dismissed"], 1)

        # Another incident: resolving must NOT set dismissed=1
        inc2_id = self.inc_repo.insert_incident(
            threat_name="Canary Tripwire",
            severity="CRITICAL",
            risk_score=90,
            affected_folder="C:\\data",
            detection_reason="Honeypot hit",
            status="ACTIVE"
        )
        self.inc_repo.resolve_incident(inc2_id)
        inc2_data = self.inc_repo.get_incident(inc2_id)
        self.assertEqual(inc2_data["status"], "RESOLVED")
        self.assertEqual(inc2_data["dismissed"], 0)

    def test_05_forensic_evidence_and_historical_data_preserved(self):
        """Confirm all evidence, file_events, and audit logs remain accessible for dismissed threats."""
        inc_id = self.inc_repo.insert_incident(
            threat_name="Ransomware Evidence Test",
            severity="HIGH",
            risk_score=80,
            affected_folder="C:\\evidence",
            affected_file="payload.exe",
            detection_reason="Known heuristic signature",
            evidence="Detailed forensic evidence block: heuristic rule 104 fired",
            sha256="abc123def456789"
        )
        self.events_repo.insert_event("CREATE", "C:\\evidence\\payload.exe", incident_id=inc_id)
        self.events_repo.insert_event("MODIFY", "C:\\evidence\\payload.exe", incident_id=inc_id)

        # Dismiss
        self.inc_repo.dismiss_incident(inc_id)

        # Threat is still in database with full forensic data intact
        inc = self.inc_repo.get_incident(inc_id)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["threat_name"], "Ransomware Evidence Test")
        self.assertEqual(inc["sha256"], "abc123def456789")
        self.assertIn("heuristic rule 104", inc["evidence"])

        # Linked file events are intact
        events = self.events_repo.get_events_by_incident(inc_id)
        self.assertEqual(len(events), 2)

    def test_06_genuinely_new_threats_appear_after_dismissal(self):
        """Confirm that dismissing earlier threats does not hide genuinely new threats with same name."""
        id_old = self.inc_repo.insert_incident(
            threat_name="Potential Ransom Note Pattern",
            severity="LOW",
            risk_score=30,
            affected_folder="C:\\docs",
            affected_file="README.md",
            detection_reason="Pattern match"
        )
        self.inc_repo.dismiss_incident(id_old)
        self.assertEqual(len(self.inc_repo.get_incidents()), 0)

        # Later, a genuinely new threat is detected with same threat_name
        id_new = self.inc_repo.insert_incident(
            threat_name="Potential Ransom Note Pattern",
            severity="LOW",
            risk_score=30,
            affected_folder="C:\\other",
            affected_file="another_file.txt",
            detection_reason="Pattern match"
        )
        visible = self.inc_repo.get_incidents()
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["id"], id_new)
        self.assertEqual(visible[0]["affected_file"], "another_file.txt")

    def test_07_threats_page_ui_row_dismiss_and_restart(self):
        """Test ThreatsPage UI: row X button dismisses, closes details, and persists across restart."""
        id_1 = self.inc_repo.insert_incident(
            threat_name="Threat Alpha",
            severity="MEDIUM",
            risk_score=50,
            affected_folder="C:\\alpha",
            affected_file="alpha.docx",
            detection_reason="Suspicious entropy"
        )
        id_2 = self.inc_repo.insert_incident(
            threat_name="Threat Beta",
            severity="HIGH",
            risk_score=80,
            affected_folder="C:\\beta",
            affected_file="beta.xlsx",
            detection_reason="Rapid write"
        )

        page = ThreatsPage(db_manager=self.db)
        page.show()
        self.assertEqual(page.model.rowCount(), 2)

        # Select row 0 to open details panel
        page._on_table_row_clicked(page.model.index(0, 0))
        self.assertFalse(page.investigation_scroll.isHidden())
        self.assertIsNotNone(page.current_incident)
        selected_id = page.current_incident["id"]

        # Determine which row corresponds to selected_id
        target_row = 0 if page.model.get_incident_at(0)["id"] == selected_id else 1

        # Dismiss that row
        page._on_dismiss_threat_clicked(target_row)

        # Details panel should be closed and current_incident cleared
        self.assertFalse(page.investigation_scroll.isVisible())
        self.assertIsNone(page.current_incident)

        # Table row count decreased immediately
        self.assertEqual(page.model.rowCount(), 1)
        remaining_id = page.model.get_incident_at(0)["id"]
        self.assertNotEqual(remaining_id, selected_id)

        # Database has persistent dismissal
        self.assertTrue(self.inc_repo.is_incident_dismissed(selected_id))
        self.assertFalse(self.inc_repo.is_incident_dismissed(remaining_id))

        # SIMULATE APPLICATION RESTART:
        # Create a new ThreatsPage instance using fresh database connection
        self.db.close_connection()
        fresh_db = DatabaseManager(self.db_path)
        if hasattr(fresh_db._local, "conn"):
            fresh_db._local.conn = None

        fresh_page = ThreatsPage(db_manager=fresh_db)
        self.assertEqual(fresh_page.model.rowCount(), 1)
        self.assertEqual(fresh_page.model.get_incident_at(0)["id"], remaining_id)
        fresh_db.close_connection()

    def test_08_details_close_button_does_not_dismiss(self):
        """Confirm Details [ × Close ] button ONLY closes details and does NOT dismiss the threat."""
        inc_id = self.inc_repo.insert_incident(
            threat_name="Threat Details Close Test",
            severity="LOW",
            risk_score=20,
            affected_folder="C:\\test",
            affected_file="test.txt",
            detection_reason="Testing close button"
        )
        page = ThreatsPage(db_manager=self.db)
        page.show()
        self.assertEqual(page.model.rowCount(), 1)

        # Click to open details
        page._on_table_row_clicked(page.model.index(0, 0))
        self.assertFalse(page.investigation_scroll.isHidden())

        # Click [ × Close ] details button
        page._on_close_details_clicked()

        # Details closed
        self.assertTrue(page.investigation_scroll.isHidden())
        self.assertIsNone(page.current_incident)

        # Threat STILL in table and NOT dismissed in DB
        self.assertEqual(page.model.rowCount(), 1)
        self.assertFalse(self.inc_repo.is_incident_dismissed(inc_id))


if __name__ == "__main__":
    unittest.main()
