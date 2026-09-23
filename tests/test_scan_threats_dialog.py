import os
import sys
import unittest
import tempfile
import shutil

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from core.database.database import DatabaseManager
from ui.components.scan_threats_dialog import ScanThreatsDialog

app = QApplication.instance() or QApplication(sys.argv)


class TestScanThreatsDialog(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_dialog.db")
        self.db = DatabaseManager(self.db_path)
        self.db.init_db()

        self.sample_threats = [
            {
                "id": 101,
                "scan_id": "test_scan_01",
                "file_path": r"E:\Data Recovery\MiniTool Power Data Recovery Business Multilingual [FileCR].zip",
                "filename": "MiniTool Power Data Recovery Business Multilingual [FileCR].zip",
                "verdict": "SUSPICIOUS",
                "severity": "LOW",
                "risk_score": 30,
                "threat_name": "Potential Ransom Note Pattern",
                "reason": "File name matches typical decryption instructions naming: 'MiniTool Power Data Recovery Business Multilingual [FileCR].zip'",
                "detection_source": "Existing File Scan",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size": 184998925,
                "file_type": "ZIP Archive / Compressed Container",
                "mtime_ns": 1764251982000000000,
                "ctime_ns": 1784690781000000000,
                "detection_time": "2026-09-22 19:50:21",
                "evidence": "Rule: Potential Ransom Note Pattern | File name matches typical decryption instructions naming | +30"
            },
            {
                "id": 102,
                "scan_id": "test_scan_01",
                "file_path": r"C:\Users\Target\Documents\invoice_urgent.exe.locked",
                "filename": "invoice_urgent.exe.locked",
                "verdict": "MALICIOUS",
                "severity": "CRITICAL",
                "risk_score": 95,
                "threat_name": "Known Ransomware Extension",
                "reason": "File extension matches known ransomware encryption pattern: .locked",
                "detection_source": "Existing File Scan",
                "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "file_size": 5242880,
                "file_type": "Executable File / PE32",
                "mtime_ns": 1764251982000000000,
                "ctime_ns": 1784690781000000000,
                "detection_time": "2026-09-22 19:50:22",
                "evidence": "Rule: KNOWN_RANSOMWARE_EXTENSION | Known ransomware extension: .locked | +95"
            }
        ]
        self.summary = {
            "scan_id": "test_scan_01",
            "files_analyzed": 500,
            "end_time": "2026-09-22 19:50:25"
        }

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def test_01_dialog_sizing_and_responsiveness(self):
        """Test 1: Dialog opens at responsive large size (>=1020x640) and size grip enabled."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        self.assertGreaterEqual(dlg.width(), 1020)
        self.assertGreaterEqual(dlg.height(), 640)
        self.assertTrue(dlg.isSizeGripEnabled())
        dlg.close()

    def test_02_splitter_proportions(self):
        """Test 2: Two-column layout uses QSplitter with correct initial proportions."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        dlg.show()
        self.assertIsNotNone(dlg.splitter)
        self.assertEqual(dlg.splitter.count(), 2)
        sizes = dlg.splitter.sizes()
        total_w = sum(sizes)
        left_pct = sizes[0] / total_w
        # Left should be between 25% and 40% of available width
        self.assertGreaterEqual(left_pct, 0.25)
        self.assertLessEqual(left_pct, 0.40)
        dlg.close()

    def test_03_left_threat_list_card_formatting(self):
        """Test 3: Left threat list contains multi-line cards with verdict, risk, and tooltips."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        self.assertEqual(dlg.threat_list.count(), 2)

        item0 = dlg.threat_list.item(0)
        self.assertIn("1. MiniTool Power Data Recovery", item0.text())
        self.assertIn("[SUSPICIOUS]", item0.text())
        self.assertIn("Risk: 30/100", item0.text())
        self.assertIn("Severity: LOW", item0.text())
        self.assertIn("MiniTool Power Data Recovery", item0.toolTip())
        dlg.close()

    def test_04_telemetry_population_and_wrapping(self):
        """Test 4: Selection updates Section A metrics, Section B file info with wordWrap, and SHA-256."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        dlg._on_threat_selected(0)

        # Section A Metric Tiles
        self.assertEqual(dlg.tile_det_type["val"].text(), "Potential Ransom Note Pattern")
        self.assertEqual(dlg.tile_verdict["val"].text(), "SUSPICIOUS")
        self.assertEqual(dlg.tile_severity["val"].text(), "LOW")
        self.assertEqual(dlg.tile_risk["val"].text(), "30 / 100")

        # Section B File Info
        self.assertEqual(dlg.meta_labels["file_name"].text(), "MiniTool Power Data Recovery Business Multilingual [FileCR].zip")
        self.assertTrue(dlg.meta_labels["full_path"].wordWrap())
        self.assertEqual(dlg.meta_labels["full_path"].text(), r"E:\Data Recovery\MiniTool Power Data Recovery Business Multilingual [FileCR].zip")
        self.assertIn("176.4 MB", dlg.meta_labels["file_size"].text())
        self.assertEqual(dlg.meta_labels["file_type"].text(), "ZIP Archive / Compressed Container")

        # SHA-256
        self.assertEqual(dlg.sha_val_lbl.text(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertTrue(dlg.btn_copy_sha.isEnabled())

        # Section C Reason & Explanation
        self.assertIn("decryption instructions naming", dlg.detection_reason_lbl.text())
        self.assertTrue(dlg.detection_reason_lbl.wordWrap())
        self.assertIn("ransom notes", dlg.why_detected_lbl.text())
        self.assertTrue(dlg.why_detected_lbl.wordWrap())
        dlg.close()

    def test_05_evidence_table_structure_and_wrapping(self):
        """Test 5: Evidence table has 4 columns (Rule, Evidence, Score, Stage) with wordWrap enabled."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        dlg._on_threat_selected(0)

        self.assertEqual(dlg.evidence_table.columnCount(), 4)
        headers = [dlg.evidence_table.horizontalHeaderItem(i).text() for i in range(4)]
        self.assertEqual(headers, ["Rule", "Observed Evidence", "Contribution / Score", "Detection Stage"])
        self.assertTrue(dlg.evidence_table.wordWrap())
        self.assertGreaterEqual(dlg.evidence_table.rowCount(), 1)
        self.assertEqual(dlg.evidence_table.item(0, 0).text(), "Potential Ransom Note Pattern")
        self.assertEqual(dlg.evidence_table.item(0, 2).text(), "+30")
        dlg.close()

    def test_06_sha256_copy_button(self):
        """Test 6: Copy SHA-256 button copies the authentic hash to clipboard."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        dlg._on_threat_selected(0)

        dlg._copy_sha256()
        clipboard_text = QApplication.clipboard().text()
        self.assertEqual(clipboard_text, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(dlg.btn_copy_sha.text(), "✓ Copied!")
        dlg.close()

    def test_07_investigate_threat_signal_emission(self):
        """Test 7: Investigate button creates incident in repository and emits investigate_threat."""
        dlg = ScanThreatsDialog(threats=self.sample_threats, scan_summary=self.summary, db_manager=self.db)
        dlg._on_threat_selected(1)

        emitted_ids = []
        dlg.investigate_threat.connect(lambda inc_id: emitted_ids.append(inc_id))

        dlg._on_investigate_clicked()
        self.assertEqual(len(emitted_ids), 1)
        self.assertGreater(emitted_ids[0], 0)

        # Confirm incident was inserted in database
        rows = self.db.execute_read("SELECT * FROM incidents WHERE id = ?", (emitted_ids[0],))
        self.assertTrue(len(rows) > 0)
        self.assertIn("invoice_urgent.exe.locked", rows[0]["affected_file"])
        dlg.close()

    def test_08_empty_threats_list_handling(self):
        """Test 8: Dialog gracefully handles an empty threats list."""
        dlg = ScanThreatsDialog(threats=[], scan_summary=self.summary, db_manager=self.db)
        self.assertEqual(dlg.threat_list.count(), 1)
        self.assertIn("No threats detected", dlg.threat_list.item(0).text())
        self.assertFalse(dlg.btn_investigate.isEnabled())
        self.assertFalse(dlg.no_selection_widget.isHidden())
        dlg.close()


if __name__ == "__main__":
    unittest.main()
