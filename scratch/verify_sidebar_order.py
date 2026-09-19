import sys
import os
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.abspath("."))

from ui.main_window import MainWindow

def main():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    window = MainWindow()
    window.resize(1280, 800)
    window.show()

    # Print button text order from sidebar safely
    buttons_text = [btn.text() for btn in window.sidebar.buttons]
    print("Sidebar Button Order:")
    for idx, t in enumerate(buttons_text, 1):
        safe_t = t.encode("ascii", "replace").decode("ascii")
        print(f"  {idx}. {safe_t}")

    from PySide6.QtCore import QTimer
    def render_and_exit():
        screenshot = window.grab()
        artifact_path = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\sidebar_reordered.png"
        screenshot.save(artifact_path, "PNG")
        print(f"\nSaved screenshot to {artifact_path}")
        window.close()
        app.quit()

    QTimer.singleShot(800, render_and_exit)
    app.exec()

if __name__ == "__main__":
    main()
