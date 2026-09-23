import sys
import os
from PySide6.QtWidgets import QApplication

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.components.scan_threats_dialog import ScanThreatsDialog

def main():
    app = QApplication.instance() or QApplication(sys.argv)

    mock_threat = {
        "id": "THREAT-2026-9901",
        "name": "WannaCry.Ransomware.Payload.exe",
        "file_path": "C:\\Users\\LENOVO\\Downloads\\WannaCry.Ransomware.Payload.exe",
        "verdict": "MALICIOUS",
        "risk_score": 98,
        "action_taken": "Quarantined",
        "quarantine_time": "2026-09-22 15:30:00",
        "sha256": "ed97d377b8cf7527e52d95e347854659b8b371a02140612dc401d90f225f1025",
        "yara_status": "Matched",
        "yara_matches": [
            {
                "rule_name": "WannaCry_Ransomware_Strings",
                "namespace": "threat.ransomware",
                "matched_file": "WannaCry.Ransomware.Payload.exe",
                "evidence": "Matched 'WanaCrypt0r' string pattern at offset 0x4A20; Matched 'wnry@cl2p' string at offset 0x5100",
                "severity": "CRITICAL"
            },
            {
                "rule_name": "Ransomware_Note_Keyword_Storm",
                "namespace": "threat.ransom_note",
                "matched_file": "WannaCry.Ransomware.Payload.exe",
                "evidence": "Rule matched 4 patterns: 'your files have been encrypted', 'how to decrypt files', 'bitcoin', 'tor browser'",
                "severity": "HIGH"
            }
        ],
        "reputation_status": "Known Malicious",
        "reputation_provider": "RansomGuard Global Threat Database",
        "reputation_score": 98,
        "detection_counts": "65/70 vendors",
        "malware_family": "WannaCry Ransomware",
        "reputation_details": "Known ransomware binary hash matching active outbreak telemetry.",
        "reputation_cached": True,
        "evidence_summary": "YARA signature rules matched 2 known ransomware patterns. Global Threat Intelligence confirms 65/70 vendor detections for WannaCry Ransomware."
    }

    dialog = ScanThreatsDialog(threats=[mock_threat])
    dialog.resize(960, 850)
    dialog.show()
    QApplication.processEvents()

    # Scroll down to reveal YARA and Threat Intel cards
    if hasattr(dialog, "details_scroll"):
        dialog.details_scroll.verticalScrollBar().setValue(dialog.details_scroll.verticalScrollBar().maximum())
    QApplication.processEvents()

    pixmap = dialog.grab()
    screenshot_path = os.path.join(os.path.dirname(__file__), "..", "threat_details_dialog_yara_intel.png")
    pixmap.save(os.path.abspath(screenshot_path))
    print(f"Saved scrolled screenshot to {os.path.abspath(screenshot_path)}")

if __name__ == "__main__":
    main()
