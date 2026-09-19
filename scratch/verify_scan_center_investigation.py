import sys
import os
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.abspath("."))

from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from ui.main_window import MainWindow

def main():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    db = DatabaseManager()
    repo = IncidentsRepository(db)

    # 1. Create main window instance
    window = MainWindow()
    window.resize(1280, 800)
    window.show()

    # 2. Simulate Scan Center single file detection record
    sample_rec = {
        "file_path": r"C:\Users\LENOVO\Desktop\README.md",
        "filename": "README.md",
        "file_size": 1637,
        "file_type": "Plain Text Document",
        "sha256": "94cb1a4cf898dece563fabc4ab8dd88ddbc7253602a7a911707548017f53206e",
        "verdict": "SUSPICIOUS",
        "severity": "LOW",
        "risk_score": 30,
        "threat_name": "Potential Ransom Note Pattern",
        "reason": "File name matches typical decryption instructions naming: 'README.md'",
        "evidence_list": [
            "Filename matches typical decryption note pattern: 'README.md'",
            "Validated file type: Plain Text Document"
        ],
        "detection_source": "Scan Center"
    }

    # 3. Pass record to scan_page and simulate clicking Investigate button
    window.scan_page._show_inspection_card(sample_rec)
    
    # Get incident ID generated / retrieved
    inc_id_1 = window.scan_page._find_or_create_incident(sample_rec)
    print(f"Generated/Found Incident ID (First Click): {inc_id_1}")
    
    inc_id_2 = window.scan_page._find_or_create_incident(sample_rec)
    print(f"Generated/Found Incident ID (Second Click - Idempotency Check): {inc_id_2}")
    
    assert inc_id_1 == inc_id_2, "FAIL: Duplicate incident created on second click!"
    print("SUCCESS: Idempotency verified - no duplicate incidents created.")

    # 4. Trigger investigate signal
    window.scan_page.investigate_incident.emit(inc_id_1)

    # Verify Threats Page status
    threats_page = window.threats_page
    current_inc = threats_page.current_incident
    
    print("\n--- THREAT REPOSITORY INVESTIGATION VERIFICATION ---")
    print(f"Active Page Index: {window.stacked_widget.currentIndex()} (Expected: 2)")
    print(f"Loaded Incident ID: {current_inc.get('id') if current_inc else 'None'}")
    print(f"Loaded Threat Name: {current_inc.get('threat_name') if current_inc else 'None'}")
    print(f"Loaded Verdict: {current_inc.get('verdict') if current_inc else 'None'}")
    print(f"Loaded Risk Score: {current_inc.get('risk_score') if current_inc else 'None'}")
    print(f"Loaded Detection Source: {threats_page.lbl_val_source.text()}")
    print(f"Loaded Full Path: {current_inc.get('full_path') if current_inc else 'None'}")
    print(f"Empty State Frame Visible: {threats_page.empty_state_frame.isVisible()} (Expected: False)")
    print(f"Table View Visible: {threats_page.table_view.isVisible()} (Expected: True)")
    print(f"Details Panel Visible: {threats_page.investigation_scroll.isVisible()} (Expected: True)")

    # Save screenshot of Threat Repository displaying the investigation
    from PySide6.QtCore import QTimer
    def render_and_exit():
        screenshot = window.grab()
        artifact_path = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\scan_center_investigation_fixed.png"
        screenshot.save(artifact_path, "PNG")
        print(f"\nSaved screenshot to {artifact_path}")
        window.close()
        app.quit()

    QTimer.singleShot(800, render_and_exit)
    app.exec()

if __name__ == "__main__":
    main()
