import sys
import os
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.abspath("."))

from ui.components.scan_threats_dialog import ScanThreatsDialog

def main():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    dlg = ScanThreatsDialog(threats=[], scan_summary={"scan_id": "test_empty_session", "files_analyzed": 100})
    dlg.show()

    from PySide6.QtCore import QTimer
    def render_and_exit():
        screenshot = dlg.grab()
        artifact_path = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\scan_threats_dialog_empty.png"
        screenshot.save(artifact_path, "PNG")
        print(f"Saved empty screenshot to {artifact_path}")
        dlg.close()
        app.quit()

    QTimer.singleShot(800, render_and_exit)
    app.exec()

if __name__ == "__main__":
    main()
