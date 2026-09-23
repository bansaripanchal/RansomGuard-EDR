import os
import sys
import time
from PIL import Image, ImageDraw, ImageFont

# Ensure workspace directory is in sys.path
workspace_dir = r"c:\Users\LENOVO\Desktop\final_project\RansomeGuard1"
if workspace_dir not in sys.path:
    sys.path.insert(0, workspace_dir)

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QPixmap

from core.database.database import DatabaseManager
from ui.pages.scan_page import ScanPage
from ui.components.image_analysis_dialog import ImageAnalysisDetailsDialog

def run_verification():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    # 1. Create a sample test image with visible and low-visibility text
    scratch_dir = os.path.join(workspace_dir, "scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    test_img_path = os.path.normpath(os.path.join(scratch_dir, "sample_hidden_text.png"))

    img = Image.new("RGB", (600, 200), color=(15, 18, 24))
    draw = ImageDraw.Draw(img)
    # Visible text
    draw.text((30, 30), "RansomGuard Visible Document Header 2026", fill=(240, 240, 240))
    # Concealed / low-visibility text (dark gray fill on dark blue background)
    draw.text((30, 110), "CONFIDENTIAL_KEY_998877", fill=(24, 28, 38))
    img.save(test_img_path)
    print(f"Sample test image saved to: {test_img_path}")

    # Initialize Database & ScanPage
    import tempfile
    temp_db_path = os.path.join(tempfile.mkdtemp(), "test_ui.db")
    db = DatabaseManager(temp_db_path)
    db.init_db()
    page = ScanPage(db_manager=db)
    page.resize(1100, 800)
    page.show()

    # Switch to Image Hidden Text Finder mode
    page._on_mode_image_text_clicked()
    app.processEvents()

    # Set target image
    page.scan_target = test_img_path
    page._set_ui_state("TARGET_SELECTED")
    page.path_label.setText(
        f"<b>Target Image</b>: sample_hidden_text.png<br>"
        f"<span style='color: #94A3B8; font-size: 11px; font-family: Consolas;'>"
        f"Path: {test_img_path} | Format: PNG | Dimensions: 600 x 200 | Size: {os.path.getsize(test_img_path):,} bytes</span>"
    )
    app.processEvents()

    # Capture Mode Selected Setup Screenshot
    artifacts_dir = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e"
    os.makedirs(artifacts_dir, exist_ok=True)
    setup_shot_path = os.path.join(artifacts_dir, "image_hidden_text_setup.png")
    pixmap = page.grab()
    pixmap.save(setup_shot_path)
    print(f"Setup screenshot saved to: {setup_shot_path}")

    # Run real image scan
    page._start_scan()
    
    # Wait for background worker to complete
    if page.image_worker:
        page.image_worker.wait()
    app.processEvents()
    time.sleep(0.5)

    # Capture Completed Results Screenshot
    result_shot_path = os.path.join(artifacts_dir, "image_hidden_text_results.png")
    pixmap_res = page.grab()
    pixmap_res.save(result_shot_path)
    print(f"Completed results screenshot saved to: {result_shot_path}")

    # Test Detailed Report Modal Dialog
    if page.current_image_result:
        dlg = ImageAnalysisDetailsDialog(page.current_image_result, parent=page)
        dlg.resize(800, 600)
        dlg.show()
        app.processEvents()

        dialog_shot_path = os.path.join(artifacts_dir, "image_analysis_dialog.png")
        pixmap_dlg = dlg.grab()
        pixmap_dlg.save(dialog_shot_path)
        print(f"Dialog screenshot saved to: {dialog_shot_path}")
        dlg.close()

    print("Verification completed successfully!")

if __name__ == "__main__":
    run_verification()
