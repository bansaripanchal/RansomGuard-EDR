import os
import sys
import time

# Ensure workspace is in sys.path
workspace_dir = r"c:\Users\LENOVO\Desktop\final_project\RansomeGuard1"
if workspace_dir not in sys.path:
    sys.path.insert(0, workspace_dir)

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QPixmap

from core.database.database import DatabaseManager
from core.protection.usb_protection_manager import USBProtectionManager, USBDevice
from ui.pages.usb_protection_page import USBProtectionPage, USBFileDetailsDialog

def capture_usb_page_screenshot():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    USBProtectionManager._instance = None
    DatabaseManager._instance = None
    db = DatabaseManager()
    db.init_db()
    usb_mgr = USBProtectionManager.get_instance(db)

    # Populate sample connected USB device
    device = USBDevice(
        drive_letter="G:",
        mount_point="G:\\",
        volume_name="Ultra_Fast_USB",
        file_system="NTFS",
        total_bytes=15728640000,
        free_bytes=3145728000,
        used_percent=80.0
    )
    device.status = "Protected"
    usb_mgr.connected_devices["G:"] = device

    page = USBProtectionPage(db)
    page.resize(1200, 800)
    page.show()

    # Simulate completed scan summary data
    sample_records = [
        {
            "file_path": r"G:\Documents\README.txt",
            "filename": "README.txt",
            "verdict": "CLEAN",
            "severity": "LOW",
            "risk_score": 30,
            "reason": "Filename matches typical decryption instructions naming: 'README.txt'",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "file_size": 1024,
            "file_type": "Plain Text Document",
            "evidence_list": ["Filename matches typical decryption instructions naming: 'README.txt'"],
            "detection_source": "USB Initial Scan"
        },
        {
            "file_path": r"G:\Scripts\base.py",
            "filename": "base.py",
            "verdict": "CLEAN",
            "severity": "LOW",
            "risk_score": 15,
            "reason": "Script contains suspicious heuristic pattern.",
            "sha256": "7a35f3d82a159f8c6b291a0c4f8260a92f8d39c05e1974711f930129a39f6048",
            "file_size": 4096,
            "file_type": "Python Source File",
            "evidence_list": ["Script contains suspicious heuristic pattern"],
            "detection_source": "USB Initial Scan"
        },
        {
            "file_path": r"G:\Tools\autorun_setup.exe",
            "filename": "autorun_setup.exe",
            "verdict": "SUSPICIOUS",
            "severity": "MEDIUM",
            "risk_score": 65,
            "reason": "Suspicious PE Section Name (.rsrc_pack) & high entropy.",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "file_size": 5242880,
            "file_type": "Portable Executable (PE32)",
            "evidence_list": ["High entropy section (.rsrc_pack)", "Imports suspicious API VirtualAllocEx"],
            "detection_source": "USB Initial Scan"
        },
        {
            "file_path": r"G:\System\Decrypter_Note.txt",
            "filename": "Decrypter_Note.txt",
            "verdict": "MALICIOUS",
            "severity": "CRITICAL",
            "risk_score": 95,
            "reason": "Known ransomware decryption instruction pattern detected.",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_size": 1024,
            "file_type": "Plain Text Document",
            "evidence_list": ["Ransom Note pattern match", "Decryption keyword density > 0.85"],
            "detection_source": "USB Initial Scan"
        }
    ]

    summary = {
        "scan_id": "8f39a022b",
        "target_drive": "G:\\",
        "duration_sec": 4.2,
        "files_discovered": 13106,
        "files_analyzed": 13106,
        "clean_count": 13104,
        "suspicious_count": 1,
        "malicious_count": 1,
        "unknown_count": 0,
        "threats_found": 2,
        "records": sample_records
    }
    page._on_scan_finished(summary)

    app.processEvents()

    # Capture main window screenshot
    pixmap = page.grab()
    artifacts_dir = r"C:\Users\LENOVO\.gemini\antigravity\brain\ea88bdb2-e3d7-45d5-ba13-d5aabcd50d8e"
    out_path = os.path.join(artifacts_dir, "usb_protection_page_redesign.png")
    pixmap.save(out_path, "PNG")
    print(f"Main page screenshot saved to: {out_path}")

    # Capture File Details Dialog screenshot
    dialog = USBFileDetailsDialog(sample_records[1], page)
    dialog.resize(650, 550)
    dialog.show()
    app.processEvents()
    dialog_pixmap = dialog.grab()
    dlg_out_path = os.path.join(artifacts_dir, "usb_file_details_dialog.png")
    dialog_pixmap.save(dlg_out_path, "PNG")
    print(f"Dialog screenshot saved to: {dlg_out_path}")

if __name__ == "__main__":
    capture_usb_page_screenshot()
