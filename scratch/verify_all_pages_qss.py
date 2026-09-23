import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from PySide6.QtGui import QPalette, QColor

# Ensure working directory is on path
sys.path.insert(0, os.path.abspath("."))

from ui.main_window import MainWindow

def capture_pages():
    app = QApplication.instance() or QApplication(sys.argv)
    
    from ui.theme import apply_theme
    apply_theme(app)

    window = MainWindow()
    window.show()

    pages = [
        ("Dashboard", 0, "dashboard_page.png"),
        ("Live Protection", 1, "live_page.png"),
        ("Threat Repository", 2, "threats_page.png"),
        ("Scan Center", 3, "scan_page.png"),
        ("Reports & Audit", 4, "reports_page.png"),
        ("History Log", 5, "history_page.png"),
        ("Settings", 6, "settings_page.png"),
        ("About", 7, "about_page.png"),
        ("USB Protection", 8, "usb_page.png")
    ]

    index = 0

    def process_next_page():
        nonlocal index
        if index < len(pages):
            title, idx, filename = pages[index]
            window.stacked_widget.setCurrentIndex(idx)
            app.processEvents()
            
            # Save screenshot
            art_dir = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e"
            filepath = os.path.join(art_dir, filename)
            screen = window.grab()
            screen.save(filepath)
            print(f"[+] Captured {title} page -> {filename}")
            
            index += 1
            QTimer.singleShot(300, process_next_page)
        else:
            window.close()
            app.quit()

    QTimer.singleShot(500, process_next_page)
    app.exec()

if __name__ == "__main__":
    capture_pages()
