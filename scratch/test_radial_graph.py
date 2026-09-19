import sys
import os
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QFrame, QLabel
from PySide6.QtCore import Qt

sys.path.insert(0, os.path.abspath("."))
from ui.components.charts import SecurityActivityPulseWidget

def test_both_states():
    app = QApplication.instance() or QApplication(sys.argv)
    
    window = QWidget()
    window.setWindowTitle("Center Text State Test")
    window.resize(650, 360)
    window.setStyleSheet("background-color: #0A0F16;")
    
    layout = QVBoxLayout(window)
    layout.setContentsMargins(15, 15, 15, 15)
    
    card = QFrame(window)
    card.setStyleSheet("""
        QFrame {
            background-color: #10161D;
            border: 1px solid #1C2630;
            border-radius: 8px;
            padding: 10px;
        }
    """)
    card_layout = QVBoxLayout(card)
    
    pulse_widget = SecurityActivityPulseWidget(card)
    card_layout.addWidget(pulse_widget)
    layout.addWidget(card)
    
    window.show()
    app.processEvents()
    
    # 1. Test COMPLETED state (26,913 / TOTAL FILES)
    pulse_widget.set_pulse_data(
        total_files=26913,
        total_files_status="done",
        drive_scope="C:\\",
        week_stats={"week_created": 55, "week_modified": 211, "week_renamed": 14, "week_deleted": 51, "week_total_events": 331}
    )
    app.processEvents()
    out_done = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\center_text_completed.png"
    card.grab().save(out_done)
    print(f"Saved completed state screenshot to: {out_done}")
    
    # 2. Test ANALYZING state (ANALYZING)
    pulse_widget.set_pulse_data(
        total_files=0,
        total_files_status="calculating",
        drive_scope="C:\\",
        week_stats={"week_created": 55, "week_modified": 211, "week_renamed": 14, "week_deleted": 51, "week_total_events": 331}
    )
    app.processEvents()
    out_analyzing = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\center_text_analyzing.png"
    card.grab().save(out_analyzing)
    print(f"Saved analyzing state screenshot to: {out_analyzing}")
    
    window.close()

if __name__ == "__main__":
    test_both_states()
