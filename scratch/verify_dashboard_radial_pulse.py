import sys
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

sys.path.insert(0, os.path.abspath("."))
from ui.main_window import MainWindow

def test_full_dashboard():
    app = QApplication.instance() or QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    app.processEvents()
    
    # Test at 1649x927 (Exact user display)
    window.resize(1649, 927)
    app.processEvents()
    
    dash_page = window.dashboard_page
    h_scroll = dash_page.scroll_area.horizontalScrollBar().isVisible()
    
    print(f"=== DASHBOARD VERIFICATION AT 1649x927 ===")
    print(f"Window geometry: {window.width()}x{window.height()}")
    print(f"Scroll Area viewport width: {dash_page.scroll_area.viewport().width()}")
    print(f"Pulse card size: {dash_page.pulse_card.width()}x{dash_page.pulse_card.height()}")
    print(f"Pulse widget size: {dash_page.pulse_widget.width()}x{dash_page.pulse_widget.height()}")
    print(f"Horizontal scrollbar visible: {h_scroll}")
    
    assert not h_scroll, "Horizontal scrollbar must not be visible!"
    
    # Save full dashboard screenshot
    out_img = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\dashboard_radial_pulse_1649x927.png"
    pixmap = dash_page.scroll_content.grab()
    pixmap.save(out_img)
    print(f"Saved full dashboard screenshot to: {out_img}")
    
    # Test 1366x768
    window.resize(1366, 768)
    app.processEvents()
    out_img_1366 = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e\dashboard_radial_pulse_1366x768.png"
    dash_page.scroll_content.grab().save(out_img_1366)
    print(f"Saved 1366x768 screenshot to: {out_img_1366}")
    
    window.close()
    print("ALL FULL DASHBOARD RADIAL GRAPH CHECKS PASSED!")

if __name__ == "__main__":
    test_full_dashboard()
