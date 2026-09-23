import json
from typing import Dict, Any

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTextEdit, QTabWidget, QWidget, QScrollArea, QSizePolicy
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class ImageAnalysisDetailsDialog(QDialog):
    """Detailed Analysis Modal Dialog for Image Hidden Text Finder."""

    def __init__(self, result: Dict[str, Any], parent=None):
        super(ImageAnalysisDetailsDialog, self).__init__(parent)
        self.result = result
        self.setWindowTitle("Image Hidden Text Analysis — Detailed Report")
        self.resize(850, 650)
        self.setMinimumSize(700, 500)
        self.setStyleSheet("""
            QDialog {
                background-color: #070B16;
                color: #F4F7FF;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            }
            QFrame#dialogCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
            QLabel {
                color: #A9B8D4;
            }
            QTabWidget::pane {
                border: 1px solid #1A2940;
                background-color: #0D1422;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #111A2B;
                color: #8B98A8;
                padding: 8px 16px;
                font-weight: 600;
                font-size: 12px;
                border: 1px solid #1A2940;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #17233A;
                color: #FFFFFF;
                border-bottom: 2px solid #168BFF;
            }
            QTextEdit {
                background-color: #0D1422;
                color: #38BDF8;
                border: 1px solid #1A2940;
                border-radius: 4px;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }
            QPushButton {
                background-color: #111A2B;
                color: #F4F7FF;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                border-color: #355B8A;
            }
        """)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 16, 16, 16)
        self.layout.setSpacing(12)

        # Header Title Card
        header_card = QFrame(self)
        header_card.setObjectName("dialogCard")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(16, 12, 16, 12)

        title_lbl = QLabel("🖼️ IMAGE HIDDEN TEXT FINDER — DETAILED REPORT", header_card)
        title_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        h_layout.addWidget(title_lbl)
        h_layout.addStretch()

        cat = result.get("category", "UNABLE TO DETERMINE")
        cat_badge = QLabel(cat, header_card)
        if "HIDDEN" in cat:
            badge_style = "background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B;"
        elif "EMBEDDED" in cat:
            badge_style = "background-color: rgba(56, 189, 248, 0.2); color: #38BDF8; border: 1px solid #38BDF8;"
        else:
            badge_style = "background-color: rgba(16, 185, 129, 0.2); color: #10B981; border: 1px solid #10B981;"

        cat_badge.setStyleSheet(f"font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 4px; {badge_style}")
        h_layout.addWidget(cat_badge)

        self.layout.addWidget(header_card)

        # Tabs for Organized Details
        self.tabs = QTabWidget(self)
        
        # Tab 1: File Info & Technical Properties
        self.tab_info = QWidget()
        self._init_info_tab(self.tab_info)
        self.tabs.addTab(self.tab_info, "📄 File & Structure")

        # Tab 2: Visible Text (OCR)
        self.tab_visible = QWidget()
        self._init_text_tab(self.tab_visible, "VISIBLE TEXT (OCR)", result.get("visible_text", "No visible text detected."))
        self.tabs.addTab(self.tab_visible, "👁️ Visible Text")

        # Tab 3: Hidden / Low-Visibility Text
        self.tab_hidden = QWidget()
        self._init_text_tab(self.tab_hidden, "HIDDEN / LOW-VISIBILITY TEXT FINDINGS", result.get("hidden_text", "No hidden text detected."))
        self.tabs.addTab(self.tab_hidden, "🔍 Hidden Text")

        # Tab 4: Channel & Transformation Analysis
        self.tab_channels = QWidget()
        self._init_channels_tab(self.tab_channels)
        self.tabs.addTab(self.tab_channels, "🎨 Channels & Transforms")

        # Tab 5: Metadata & EXIF
        self.tab_meta = QWidget()
        self._init_meta_tab(self.tab_meta)
        self.tabs.addTab(self.tab_meta, "🏷️ Metadata")

        # Tab 6: Embedded Data & Security Interpretation
        self.tab_sec = QWidget()
        self._init_sec_tab(self.tab_sec)
        self.tabs.addTab(self.tab_sec, "🛡️ Security Interpretation")

        self.layout.addWidget(self.tabs, 1)

        # Bottom Action Row
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close Report", self)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        self.layout.addLayout(btn_row)

    def _init_info_tab(self, widget: QWidget):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        
        txt = QTextEdit(widget)
        txt.setReadOnly(True)
        r = self.result
        
        info_lines = [
            "FILE INFORMATION:",
            f"  • File Name:     {r.get('filename', 'N/A')}",
            f"  • Full Path:     {r.get('file_path', 'N/A')}",
            f"  • File Size:     {r.get('file_size', 0):,} bytes",
            f"  • Image Format:  {r.get('file_format', 'N/A')}",
            f"  • Dimensions:    {r.get('dimensions', 'N/A')}",
            f"  • Color Mode:    {r.get('color_mode', 'N/A')}",
            f"  • SHA-256 Hash:  {r.get('sha256', 'N/A')}",
            f"  • Analysis Time: {r.get('duration_sec', 0.0)} seconds",
            "",
            "ANALYSIS METHODOLOGY:",
            f"  • Primary Method: {r.get('detection_method', 'N/A')}",
            f"  • Overall Category: {r.get('category', 'N/A')}"
        ]
        txt.setPlainText("\n".join(info_lines))
        layout.addWidget(txt)

    def _init_text_tab(self, widget: QWidget, title: str, content: str):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        
        lbl = QLabel(title, widget)
        lbl.setStyleSheet("font-weight: bold; color: #94A3B8; margin-bottom: 4px;")
        layout.addWidget(lbl)

        txt = QTextEdit(widget)
        txt.setReadOnly(True)
        txt.setPlainText(content)
        layout.addWidget(txt)

    def _init_channels_tab(self, widget: QWidget):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        
        txt = QTextEdit(widget)
        txt.setReadOnly(True)
        channels = self.result.get("channel_findings", [])
        
        lines = ["INDEPENDENT CHANNEL ANALYSIS:"]
        if channels:
            for ch in channels:
                lines.append(f"\n[Channel: {ch.get('channel')}]")
                lines.append(f"  • Mean Luminance: {ch.get('mean_luminance')}")
                lines.append(f"  • Std Deviation:  {ch.get('std_deviation')}")
                lines.append(f"  • Pixel Range:    {ch.get('pixel_range')}")
                lines.append(f"  • Text Detected:  {ch.get('text_detected')}")
                if ch.get('details'):
                    lines.append(f"  • Findings:       {ch.get('details')}")
        else:
            lines.append("  No channel anomaly reported.")

        layout.addWidget(txt)

    def _init_meta_tab(self, widget: QWidget):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        
        txt = QTextEdit(widget)
        txt.setReadOnly(True)
        meta = self.result.get("metadata", {})
        
        lines = ["EXTRACTED IMAGE METADATA & EXIF DATA:"]
        if isinstance(meta, dict) and meta:
            lines.append(json.dumps(meta, indent=2))
        else:
            lines.append("  No metadata detected.")

        txt.setPlainText("\n".join(lines))
        layout.addWidget(txt)

    def _init_sec_tab(self, widget: QWidget):
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        
        txt = QTextEdit(widget)
        txt.setReadOnly(True)
        sec_text = self.result.get("security_interpretation", "No security interpretation available.")
        txt.setPlainText(sec_text)
        layout.addWidget(txt)
