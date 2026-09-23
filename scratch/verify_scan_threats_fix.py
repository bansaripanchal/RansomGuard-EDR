import sys
import os
from PySide6.QtWidgets import QApplication

# Ensure workspace is in path
sys.path.insert(0, os.path.abspath("."))

from core.scanning.existing_scan_manager import ExistingScanManager
from core.database.database import DatabaseManager
from ui.components.scan_threats_dialog import ScanThreatsDialog

def main():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    from ui.theme import apply_theme
    apply_theme(app)

    db = DatabaseManager()
    mgr = ExistingScanManager(db_manager=db)

    threats = mgr.get_last_scan_threats()
    summary = mgr.get_last_scan_summary() or {}

    print(f"Loaded {len(threats)} threats for scan summary: {summary.get('scan_id')}")

    dlg = ScanThreatsDialog(threats=threats, scan_summary=summary, db_manager=db)
    dlg.show()

    # Take screenshot of dialog after 500ms
    from PySide6.QtCore import QTimer
    def render_and_exit():
        screenshot = dlg.grab()
        artifact_path = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\scan_threats_dialog_fixed.png"
        screenshot.save(artifact_path, "PNG")
        print(f"Saved screenshot to {artifact_path}")
        dlg.close()
        app.quit()

    QTimer.singleShot(800, render_and_exit)
    app.exec()

if __name__ == "__main__":
    main()
