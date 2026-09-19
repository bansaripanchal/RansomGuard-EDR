import unittest
import os
import tempfile
import time
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository
from core.database.history_repository import HistoryRepository
from core.database.settings_repository import SettingsRepository
from core.reporting.pdf_report import PDFReportGenerator
from core.reporting.csv_report import CSVReportGenerator

class TestReportingPipeline(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.db = DatabaseManager(self.db_path)
        if hasattr(self.db._local, "conn"):
            self.db._local.conn = None

        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.settings_repo = SettingsRepository(self.db)

        # Clear tables
        self.db.execute_write("DELETE FROM file_events")
        self.db.execute_write("DELETE FROM incidents")
        self.db.execute_write("DELETE FROM history_log")
        self.db.execute_write("DELETE FROM monitored_paths")
        self.db.execute_write("DELETE FROM settings")

        # Set protected drive to E:
        self.settings_repo.set_setting("protected_drives", "E:")
        self.settings_repo.add_monitored_path("E:\\", recursive=True)

        # Populate real test incident on E:
        self.test_inc_id = self.inc_repo.insert_incident(
            threat_name="Mass File Modification",
            severity="HIGH",
            risk_score=90,
            affected_folder="E:\\RansomGuard_Test",
            affected_file="Multiple Files",
            full_path="E:\\RansomGuard_Test",
            detection_reason="Mass file modifications and extensions altered.",
            created_count=5,
            modified_count=20,
            renamed_count=15,
            deleted_count=2,
            process_pid=None,
            process_name="Unknown",
            recommendation="Review affected files and restore uncorrupted copies from backup."
        )

        # Populate file events linked to this incident on E:
        events = []
        for i in range(10):
            events.append(("MODIFY", f"E:\\RansomGuard_Test\\doc_{i}.txt", None, ".txt", 1024, self.test_inc_id))
            events.append(("RENAME", f"E:\\RansomGuard_Test\\doc_{i}.txt", f"E:\\RansomGuard_Test\\doc_{i}.locked", ".locked", 2048, self.test_inc_id))
        self.events_repo.insert_events_batch(events)

        # Populate history log
        self.history_repo.insert_log(
            event_type="THREAT_DETECTED",
            severity="HIGH",
            description="Security incident detected in E:\\RansomGuard_Test",
            target="E:\\RansomGuard_Test",
            action_taken="ALERT_GENERATED"
        )

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

    def test_scope_clause_matches_e_drive(self):
        scope_clause, scope_params = self.db.get_active_scope_clause("affected_folder")
        incidents = self.db.execute_read(f"SELECT * FROM incidents WHERE {scope_clause}", tuple(scope_params))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["affected_folder"], "E:\\RansomGuard_Test")

        ev_clause, ev_params = self.db.get_active_scope_clause("src_path")
        file_events = self.db.execute_read(f"SELECT * FROM file_events WHERE {ev_clause}", tuple(ev_params))
        self.assertEqual(len(file_events), 20)

    def test_single_threat_pdf_report_generation(self):
        fd, out_pdf = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        try:
            generator = PDFReportGenerator(
                output_path=out_pdf,
                report_type="threat_incident",
                incident_id=self.test_inc_id,
                db_manager=self.db
            )
            generator.run()

            self.assertTrue(os.path.exists(out_pdf))
            self.assertGreater(os.path.getsize(out_pdf), 1000)
        finally:
            if os.path.exists(out_pdf):
                try:
                    os.remove(out_pdf)
                except Exception:
                    pass

    def test_executive_pdf_report_generation(self):
        fd, out_pdf = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        try:
            generator = PDFReportGenerator(
                output_path=out_pdf,
                report_type="executive",
                db_manager=self.db
            )
            generator.run()

            self.assertTrue(os.path.exists(out_pdf))
            self.assertGreater(os.path.getsize(out_pdf), 1000)
        finally:
            if os.path.exists(out_pdf):
                try:
                    os.remove(out_pdf)
                except Exception:
                    pass

    def test_incidents_and_events_pdf_reports(self):
        for r_type in ("incidents", "events", "history"):
            fd, out_pdf = tempfile.mkstemp(suffix=".pdf")
            os.close(fd)
            try:
                generator = PDFReportGenerator(
                    output_path=out_pdf,
                    report_type=r_type,
                    db_manager=self.db
                )
                generator.run()

                self.assertTrue(os.path.exists(out_pdf))
                self.assertGreater(os.path.getsize(out_pdf), 1000)
            finally:
                if os.path.exists(out_pdf):
                    try:
                        os.remove(out_pdf)
                    except Exception:
                        pass

    def test_csv_exports(self):
        for r_type in ("incidents", "events", "history"):
            fd, out_csv = tempfile.mkstemp(suffix=".csv")
            os.close(fd)
            try:
                generator = CSVReportGenerator(
                    output_path=out_csv,
                    report_type=r_type,
                    db_manager=self.db
                )
                generator.run()

                self.assertTrue(os.path.exists(out_csv))
                self.assertGreater(os.path.getsize(out_csv), 50)
                
                with open(out_csv, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    self.assertGreater(len(lines), 1)
            finally:
                if os.path.exists(out_csv):
                    try:
                        os.remove(out_csv)
                    except Exception:
                        pass

if __name__ == "__main__":
    unittest.main()
