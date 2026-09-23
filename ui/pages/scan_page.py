import os
import time
import hashlib
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame, 
    QProgressBar, QFileDialog, QTableView, QHeaderView, QTextEdit,
    QGridLayout, QScrollArea, QSizePolicy
)
from PySide6.QtCore import Qt, QEvent, Signal
from PySide6.QtGui import QPixmap, QIcon

from core.scanning.scanner import BackgroundScanner
from core.scanning.image_scan_worker import ImageScanWorker
from core.scanning.image_text_finder import SUPPORTED_FORMATS
from ui.components.image_analysis_dialog import ImageAnalysisDetailsDialog
from ui.components.tables import ScanResultsTableModel, format_file_size
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository

class ScanPage(QWidget):
    investigate_incident = Signal(int)

    def __init__(self, db_manager=None, parent=None):
        super(ScanPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.current_record = None
        self.scan_mode = "FILE_SECURITY" # "FILE_SECURITY" or "IMAGE_TEXT"
        self.image_worker = None
        self.current_image_result = None
        
        # Outer layout: Houses the single main vertical scroll area
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # -------------------------------------------------------------
        # 1. Main Page Scroll Area (Single outer vertical scroll container)
        # -------------------------------------------------------------
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")

        # Scrollable inner content widget containing all 4 sections in order
        self.scroll_content = QWidget()
        self.scroll_content.setObjectName("scanScrollContent")
        self.content_layout = QVBoxLayout(self.scroll_content)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.content_layout.setSpacing(16)

        # -------------------------------------------------------------
        # Mode Selection Bar (Target Security Scan vs Image Hidden Text Finder)
        # -------------------------------------------------------------
        self.mode_card = QFrame(self.scroll_content)
        self.mode_card.setStyleSheet("""
            QFrame {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 4px;
            }
        """)
        mode_layout = QHBoxLayout(self.mode_card)
        mode_layout.setContentsMargins(4, 4, 4, 4)
        mode_layout.setSpacing(8)

        self.btn_mode_security = QPushButton("🎯 File & Folder Security Scan", self.mode_card)
        self.btn_mode_security.setCursor(Qt.PointingHandCursor)
        self.btn_mode_security.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #168BFF;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        self.btn_mode_security.clicked.connect(self._on_mode_security_clicked)

        self.btn_mode_image_text = QPushButton("🖼️ Image Hidden Text Finder", self.mode_card)
        self.btn_mode_image_text.setCursor(Qt.PointingHandCursor)
        self.btn_mode_image_text.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #A9B8D4;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #21334D;
            }
        """)
        self.btn_mode_image_text.clicked.connect(self._on_mode_image_text_clicked)

        mode_layout.addWidget(self.btn_mode_security)
        mode_layout.addWidget(self.btn_mode_image_text)
        mode_layout.addStretch()

        self.content_layout.addWidget(self.mode_card)

        # -------------------------------------------------------------
        # Section 1: TARGET FOLDER / FILE SECURITY SCAN (Configuration Card)
        # -------------------------------------------------------------
        self.config_card = QFrame(self.scroll_content)
        self.config_card.setProperty("class", "metricCard")
        self.config_layout = QVBoxLayout(self.config_card)
        self.config_layout.setSpacing(12)

        self.card_title = QLabel("🔍 TARGET FOLDER / FILE SECURITY SCAN", self.config_card)
        self.card_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px;")
        self.config_layout.addWidget(self.card_title)

        # Target Selection Row
        self.target_row = QHBoxLayout()
        self.select_folder_btn = QPushButton("📁 Browse Folder...", self.config_card)
        self.select_folder_btn.setProperty("class", "secondaryButton")
        self.select_folder_btn.setCursor(Qt.PointingHandCursor)
        
        self.select_file_btn = QPushButton("📄 Browse File...", self.config_card)
        self.select_file_btn.setProperty("class", "secondaryButton")
        self.select_file_btn.setCursor(Qt.PointingHandCursor)

        self.start_scan_btn = QPushButton("🚀 Run Security Scan", self.config_card)
        self.start_scan_btn.setProperty("class", "primaryButton")
        self.start_scan_btn.setCursor(Qt.PointingHandCursor)
        self.start_scan_btn.setEnabled(False)

        self.cancel_scan_btn = QPushButton("⏹️ Cancel", self.config_card)
        self.cancel_scan_btn.setProperty("class", "actionRedButton")
        self.cancel_scan_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_scan_btn.setVisible(False)

        self.target_row.addWidget(self.select_folder_btn)
        self.target_row.addWidget(self.select_file_btn)
        self.target_row.addWidget(self.start_scan_btn)
        self.target_row.addWidget(self.cancel_scan_btn)
        self.target_row.addStretch()
        self.config_layout.addLayout(self.target_row)

        # Selected Path label (with text wrapping to prevent horizontal stretching)
        self.path_label = QLabel("<b>Target Path</b>: None selected", self.config_card)
        self.path_label.setStyleSheet("color: #FFFFFF; font-size: 13px;")
        self.path_label.setWordWrap(True)
        self.config_layout.addWidget(self.path_label)

        self.content_layout.addWidget(self.config_card)

        # -------------------------------------------------------------
        # Section 2: SCAN RESULT / PROGRESS
        # -------------------------------------------------------------
        self.progress_card = QFrame(self.scroll_content)
        self.progress_card.setProperty("class", "metricCard")
        self.progress_layout = QVBoxLayout(self.progress_card)
        self.progress_layout.setSpacing(10)

        self.progress_title = QLabel("Scan Telemetry Status: IDLE", self.progress_card)
        self.progress_title.setStyleSheet("font-weight: bold; color: #9CA3AF;")
        self.progress_layout.addWidget(self.progress_title)

        self.progress_bar = QProgressBar(self.progress_card)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1A2940;
                border-radius: 4px;
                text-align: center;
                background-color: #0D1422;
                height: 18px;
                color: #FFFFFF;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                border-radius: 3px;
            }
        """)
        self.progress_bar.setValue(0)
        self.progress_layout.addWidget(self.progress_bar)

        self.current_file_label = QLabel("", self.progress_card)
        self.current_file_label.setStyleSheet("color: #9CA3AF; font-size: 11px; font-family: Consolas;")
        self.current_file_label.setWordWrap(True)
        self.progress_layout.addWidget(self.current_file_label)

        self.content_layout.addWidget(self.progress_card)
        self.progress_card.setVisible(False) # Hide progress until active

        # -------------------------------------------------------------
        # Section 3: FILE ANALYSIS EVIDENCE & VERDICT
        # -------------------------------------------------------------
        self.single_card = QFrame(self.scroll_content)
        self.single_card.setObjectName("scanEvidenceCard")
        self.single_card.setStyleSheet("""
            QFrame#scanEvidenceCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        self.single_layout = QVBoxLayout(self.single_card)
        self.single_layout.setContentsMargins(10, 8, 10, 8)
        self.single_layout.setSpacing(8)
        
        # 1. Header Row: Title, Badges, and Investigate Action Button
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        self.single_title = QLabel("🛡️ FILE ANALYSIS EVIDENCE & VERDICT", self.single_card)
        self.single_title.setStyleSheet("font-weight: 800; color: #9CA3AF; font-size: 12px; letter-spacing: 0.5px;")
        header_row.addWidget(self.single_title)

        self.single_verdict_badge = QLabel("VERDICT: PENDING", self.single_card)
        self.single_verdict_badge.setStyleSheet("font-size: 11px; font-weight: bold; padding: 3px 8px; border-radius: 4px;")
        header_row.addWidget(self.single_verdict_badge)

        self.single_risk_badge = QLabel("Risk: -", self.single_card)
        self.single_risk_badge.setStyleSheet("""
            background-color: rgba(249, 115, 22, 0.15);
            color: #F97316;
            font-size: 11px;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid rgba(249, 115, 22, 0.3);
        """)
        header_row.addWidget(self.single_risk_badge)

        self.single_source_badge = QLabel("Source: Scan Center", self.single_card)
        self.single_source_badge.setStyleSheet("""
            background-color: #111A2B;
            color: #A855F7;
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid #1A2940;
        """)
        header_row.addWidget(self.single_source_badge)

        header_row.addStretch()

        # Investigate / View Details button in Threat Repository
        self.btn_investigate = QPushButton("🔍 Investigate in Threat Repository →", self.single_card)
        self.btn_investigate.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #38A8FF;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #70BFFF;
                border-color: #355B8A;
            }
        """)
        self.btn_investigate.setCursor(Qt.PointingHandCursor)
        self.btn_investigate.clicked.connect(self._on_investigate_clicked)
        self.btn_investigate.setVisible(False)
        header_row.addWidget(self.btn_investigate)

        self.single_layout.addLayout(header_row)

        # 2. Telemetry Details Grid (Two columns of clean label-and-value pairs)
        grid_frame = QFrame(self.single_card)
        grid_frame.setStyleSheet("background: transparent; border: none;")
        grid_layout = QGridLayout(grid_frame)
        grid_layout.setContentsMargins(0, 2, 0, 2)
        grid_layout.setHorizontalSpacing(24)
        grid_layout.setVerticalSpacing(4)

        def _make_field(lbl_text):
            lbl = QLabel(lbl_text, grid_frame)
            lbl.setFixedWidth(115)
            lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: 600;")
            val = QLabel("-", grid_frame)
            val.setStyleSheet("color: #E6EDF3; font-size: 11px; font-weight: 500;")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            h = QHBoxLayout()
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(8)
            h.addWidget(lbl)
            h.addWidget(val, 1)
            return h, val

        # Left Column: File Name, Full Path, File Size, File Type
        h_fn, self.val_filename = _make_field("File Name:")
        self.val_filename.setStyleSheet("color: #FFFFFF; font-size: 11px; font-weight: 700;")
        grid_layout.addLayout(h_fn, 0, 0)

        h_fp, self.val_path = _make_field("Full Path:")
        self.val_path.setStyleSheet("color: #CBD5E1; font-size: 11px; font-family: Consolas;")
        grid_layout.addLayout(h_fp, 1, 0)

        h_fs, self.val_size = _make_field("File Size:")
        grid_layout.addLayout(h_fs, 2, 0)

        h_ft, self.val_type = _make_field("File Type:")
        grid_layout.addLayout(h_ft, 3, 0)

        # Right Column: Verdict, Risk Score, Detection Source, Detection Rule
        h_vd, self.val_verdict = _make_field("Verdict:")
        grid_layout.addLayout(h_vd, 0, 1)

        h_rs, self.val_risk = _make_field("Risk Score:")
        grid_layout.addLayout(h_rs, 1, 1)

        h_ds, self.val_source = _make_field("Detection Source:")
        grid_layout.addLayout(h_ds, 2, 1)

        h_dr, self.val_rule = _make_field("Detection Rule:")
        self.val_rule.setStyleSheet("color: #38BDF8; font-size: 11px; font-family: Consolas; font-weight: 600;")
        grid_layout.addLayout(h_dr, 3, 1)

        # SHA-256 (Spans across bottom of grid, wrapping enabled)
        h_sh, self.val_sha256 = _make_field("SHA-256:")
        self.val_sha256.setStyleSheet("color: #94A3B8; font-size: 11px; font-family: Consolas;")
        grid_layout.addLayout(h_sh, 4, 0, 1, 2)

        self.single_layout.addWidget(grid_frame)

        # 3. Detection Reason Banner
        self.reason_frame = QFrame(self.single_card)
        self.reason_frame.setStyleSheet("""
            QFrame {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-left: 3px solid #FFB84D;
                border-radius: 4px;
                padding: 5px 8px;
            }
        """)
        rf_layout = QHBoxLayout(self.reason_frame)
        rf_layout.setContentsMargins(4, 2, 4, 2)
        rf_layout.setSpacing(6)

        self.val_reason = QLabel("Detection Reason: None", self.reason_frame)
        self.val_reason.setStyleSheet("color: #CBD5E1; font-size: 11px; font-weight: 500; background: transparent; border: none;")
        self.val_reason.setWordWrap(True)
        self.val_reason.setTextInteractionFlags(Qt.TextSelectableByMouse)
        rf_layout.addWidget(self.val_reason, 1)

        self.single_layout.addWidget(self.reason_frame)

        # 4. Detection Evidence & Applied Rules Section
        # Grows naturally without tiny fixed-height scrollbars; main page handles vertical scroll
        ev_title = QLabel("Detection Evidence & Observed Indicators:", self.single_card)
        ev_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #8B98A8; margin-top: 1px;")
        self.single_layout.addWidget(ev_title)

        self.single_evidence_view = QTextEdit(self.single_card)
        self.single_evidence_view.setReadOnly(True)
        self.single_evidence_view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.single_evidence_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.single_evidence_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.single_evidence_view.setStyleSheet("""
            QTextEdit {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 4px;
                color: #F4F7FF;
                font-family: Consolas;
                font-size: 11px;
                padding: 6px 8px;
            }
        """)
        self.single_layout.addWidget(self.single_evidence_view)

        self.content_layout.addWidget(self.single_card)
        self.single_card.setVisible(False)

        # -------------------------------------------------------------
        # Section 4: SCAN RESULTS & EVIDENCE AUDIT (Results Table & Compact Empty State)
        # -------------------------------------------------------------
        self.results_card = QFrame(self.scroll_content)
        self.results_card.setProperty("class", "metricCard")
        self.results_layout = QVBoxLayout(self.results_card)
        self.results_layout.setContentsMargins(14, 12, 14, 12)
        self.results_layout.setSpacing(10)
        
        self.results_title = QLabel("🔍 SCAN RESULTS & EVIDENCE AUDIT", self.results_card)
        self.results_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 12px; margin-bottom: 2px;")
        self.results_layout.addWidget(self.results_title)

        # Compact Empty State Container (Displayed when no scan has been performed yet)
        self.empty_state_container = QFrame(self.results_card)
        self.empty_state_container.setObjectName("scanEmptyStateContainer")
        self.empty_state_container.setStyleSheet("""
            QFrame#scanEmptyStateContainer {
                background-color: #0D1422;
                border: 1px dashed #1A2940;
                border-radius: 6px;
                padding: 16px 14px;
            }
        """)
        esc_layout = QVBoxLayout(self.empty_state_container)
        esc_layout.setContentsMargins(8, 6, 8, 6)
        esc_layout.setSpacing(4)
        esc_layout.setAlignment(Qt.AlignCenter)

        self.empty_icon = QLabel("🔍", self.empty_state_container)
        self.empty_icon.setAlignment(Qt.AlignCenter)
        self.empty_icon.setStyleSheet("font-size: 26px; background: transparent; border: none; margin-bottom: 2px;")
        esc_layout.addWidget(self.empty_icon)

        self.empty_title = QLabel("Ready to Scan", self.empty_state_container)
        self.empty_title.setAlignment(Qt.AlignCenter)
        self.empty_title.setStyleSheet("font-size: 13px; font-weight: bold; color: #E2E8F0; background: transparent; border: none;")
        esc_layout.addWidget(self.empty_title)

        self.empty_desc = QLabel("Select a folder or file above to begin a security scan.", self.empty_state_container)
        self.empty_desc.setAlignment(Qt.AlignCenter)
        self.empty_desc.setStyleSheet("font-size: 11px; color: #94A3B8; background: transparent; border: none;")
        esc_layout.addWidget(self.empty_desc)

        self.empty_hint = QLabel("No scan results are available yet.", self.empty_state_container)
        self.empty_hint.setAlignment(Qt.AlignCenter)
        self.empty_hint.setStyleSheet("font-size: 11px; color: #64748B; background: transparent; border: none;")
        esc_layout.addWidget(self.empty_hint)

        self.results_layout.addWidget(self.empty_state_container)

        # Custom Table for detected threats in the scan (Hidden until scan is executed)
        self.table_view = QTableView(self.results_card)
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setEditTriggers(QTableView.NoEditTriggers)
        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.table_model = ScanResultsTableModel(parent=self)
        self.table_view.setModel(self.table_model)

        self.results_layout.addWidget(self.table_view)
        self.content_layout.addWidget(self.results_card)

        # Bottom stretch to prevent empty cards from stretching vertically across the window
        self.content_layout.addStretch(1)

        # Connect scroll content to main scroll area
        self.scroll_area.setWidget(self.scroll_content)
        self.main_layout.addWidget(self.scroll_area)

        # Clean state label for results table (Used when scan completed with 0 threats)
        self.empty_label = QLabel("No security threats detected.", self.table_view)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #22C55E; font-size: 13px; font-weight: bold;")
        self.table_view.installEventFilter(self)

        # Connect slots
        self.select_folder_btn.clicked.connect(self._select_folder)
        self.select_file_btn.clicked.connect(self._select_file)
        self.start_scan_btn.clicked.connect(self._start_scan)
        self.cancel_scan_btn.clicked.connect(self._cancel_scan)
        self.table_view.clicked.connect(self._on_table_row_clicked)
        self.table_view.doubleClicked.connect(self._on_table_row_double_clicked)

        self.scan_target = None
        self.scanner = None
        self.current_ui_state = "INITIAL"
        self._set_ui_state("INITIAL")

    def _on_mode_security_clicked(self):
        self.scan_mode = "FILE_SECURITY"
        self.btn_mode_security.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #168BFF;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        self.btn_mode_image_text.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #A9B8D4;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #21334D;
            }
        """)
        self.card_title.setText("🔍 TARGET FOLDER / FILE SECURITY SCAN")
        self.select_folder_btn.setVisible(True)
        self.select_file_btn.setText("📄 Browse File...")
        self.start_scan_btn.setText("🚀 Run Security Scan")
        self.results_title.setText("🔍 SCAN RESULTS & EVIDENCE AUDIT")
        self._set_ui_state("INITIAL")

    def _on_mode_image_text_clicked(self):
        self.scan_mode = "IMAGE_TEXT"
        self.btn_mode_image_text.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #168BFF;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        self.btn_mode_security.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #A9B8D4;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #21334D;
            }
        """)
        self.card_title.setText("🖼️ IMAGE HIDDEN TEXT FINDER")
        self.select_folder_btn.setVisible(False)
        self.select_file_btn.setText("🖼️ Select Image...")
        self.start_scan_btn.setText("🚀 Run Image Text Analysis")
        self.results_title.setText("🖼️ IMAGE ANALYSIS RESULTS & EVIDENCE")
        self._set_ui_state("INITIAL")
        self.empty_icon.setText("🖼️")
        self.empty_title.setText("Ready for Image Hidden Text Analysis")
        self.empty_desc.setText("Select an image above (PNG, JPG, BMP, TIFF, WEBP) to begin real hidden text analysis.")

    def _set_ui_state(self, state: str):
        """Manages Scan Center UI states: INITIAL, TARGET_SELECTED, SCANNING, COMPLETED."""
        self.current_ui_state = state
        if state == "INITIAL":
            self.scan_target = None
            self.path_label.setText("<b>Target Path</b>: None selected")
            self.start_scan_btn.setEnabled(False)
            self.cancel_scan_btn.setVisible(False)
            self.progress_card.setVisible(False)
            self.single_card.setVisible(False)
            self.empty_state_container.setVisible(True)
            self.empty_icon.setText("🖼️" if self.scan_mode == "IMAGE_TEXT" else "🔍")
            self.empty_title.setText("Ready for Image Hidden Text Analysis" if self.scan_mode == "IMAGE_TEXT" else "Ready to Scan")
            self.empty_desc.setText("Select an image above to begin real hidden text analysis." if self.scan_mode == "IMAGE_TEXT" else "Select a folder or file above to begin a security scan.")
            self.empty_hint.setText("No scan results are available yet.")
            self.table_view.setVisible(False)
            self.empty_label.hide()

        elif state == "TARGET_SELECTED":
            self.start_scan_btn.setEnabled(True)
            self.cancel_scan_btn.setVisible(False)
            self.progress_card.setVisible(False)
            self.single_card.setVisible(False)
            self.empty_state_container.setVisible(True)
            is_dir = self.scan_target and os.path.isdir(self.scan_target)
            self.empty_icon.setText("🖼️" if self.scan_mode == "IMAGE_TEXT" else ("📁" if is_dir else "📄"))
            self.empty_title.setText("Ready to Scan")
            target_name = os.path.basename(self.scan_target) if self.scan_target else "Selected target"
            btn_txt = "Run Image Text Analysis" if self.scan_mode == "IMAGE_TEXT" else "Run Security Scan"
            self.empty_desc.setText(f"Target selected: '{target_name}'. Click '{btn_txt}' above to begin.")
            self.empty_hint.setText("No scan results are available yet.")
            self.table_view.setVisible(False)
            self.empty_label.hide()

        elif state == "SCANNING":
            self.start_scan_btn.setEnabled(False)
            self.select_folder_btn.setEnabled(False)
            self.select_file_btn.setEnabled(False)
            self.cancel_scan_btn.setVisible(True)
            self.progress_card.setVisible(True)
            self.single_card.setVisible(False)
            self.empty_state_container.setVisible(False)
            self.table_view.setVisible(self.scan_mode != "IMAGE_TEXT")

        elif state == "COMPLETED":
            self.start_scan_btn.setEnabled(True)
            self.select_folder_btn.setEnabled(True)
            self.select_file_btn.setEnabled(True)
            self.cancel_scan_btn.setVisible(False)
            self.progress_card.setVisible(True)
            self.empty_state_container.setVisible(False)
            self.table_view.setVisible(self.scan_mode != "IMAGE_TEXT")

    def _select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if folder:
            self.scan_target = os.path.normpath(folder)
            self.path_label.setText(f"<b>Target Path</b>: {self.scan_target} (Folder)")
            self.table_model.clear()
            self._set_ui_state("TARGET_SELECTED")

    def _select_file(self):
        if self.scan_mode == "IMAGE_TEXT":
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Image for Hidden Text Analysis", "",
                "Supported Image Files (*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp);;PNG Files (*.png);;JPEG Files (*.jpg *.jpeg);;Bitmap Files (*.bmp);;TIFF Files (*.tiff *.tif);;WEBP Files (*.webp);;All Files (*.*)"
            )
            if file_path:
                self.scan_target = os.path.normpath(file_path)
                ext = os.path.splitext(self.scan_target)[1].lstrip(".").upper()
                if ext not in SUPPORTED_FORMATS and ext != "MPO":
                    self.path_label.setText(
                        f"<b>Target Image</b>: {os.path.basename(self.scan_target)} — "
                        "<span style='color: #EF4444; font-weight: bold;'>Unsupported image format</span>"
                    )
                    self.start_scan_btn.setEnabled(False)
                    return

                try:
                    file_size = os.path.getsize(self.scan_target)
                    from PIL import Image
                    with Image.open(self.scan_target) as img:
                        w, h = img.size
                        fmt = img.format or ext
                        mode = img.mode
                    dim_str = f"{w} x {h}"
                except Exception:
                    dim_str = "Unknown dimensions"
                    file_size = 0
                    fmt = ext

                self.path_label.setText(
                    f"<b>Target Image</b>: {os.path.basename(self.scan_target)}<br>"
                    f"<span style='color: #94A3B8; font-size: 11px; font-family: Consolas;'>"
                    f"Path: {self.scan_target} | Format: {fmt} | Dimensions: {dim_str} | Size: {file_size:,} bytes</span>"
                )
                self.table_model.clear()
                self._set_ui_state("TARGET_SELECTED")
                self.empty_icon.setText("🖼️")
                self.empty_title.setText("Image Ready for Analysis")
                self.empty_desc.setText(f"Target selected: '{os.path.basename(self.scan_target)}'. Click 'Run Image Text Analysis' above to begin.")
        else:
            file, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
            if file:
                self.scan_target = os.path.normpath(file)
                self.path_label.setText(f"<b>Target Path</b>: {self.scan_target} (File)")
                self.table_model.clear()
                self._set_ui_state("TARGET_SELECTED")

    def _start_scan(self):
        if not self.scan_target:
            return

        if self.scan_mode == "IMAGE_TEXT":
            self._set_ui_state("SCANNING")
            self.table_model.clear()
            self.progress_bar.setValue(0)
            self.progress_bar.setRange(0, 100)
            self.progress_title.setText("Image Analysis Status: RUNNING...")
            self.current_file_label.setText(f"Analyzing image {self.scan_target}...")
            self.empty_label.setText("Analyzing image structure & text...")
            self.empty_label.setStyleSheet("color: #94A3B8; font-size: 13px; font-weight: bold;")
            self.empty_label.show()

            self.image_worker = ImageScanWorker(self.scan_target, db_manager=self.db, parent=self)
            self.image_worker.progress_updated.connect(self._on_image_progress_updated)
            self.image_worker.scan_completed.connect(self._on_image_scan_completed)
            self.image_worker.scan_failed.connect(self._on_scan_error)
            self.image_worker.start()
        else:
            self._set_ui_state("SCANNING")
            self.table_model.clear()
            self.progress_bar.setValue(0)
            self.progress_bar.setRange(0, 0) # Indeterminate mode until we start processing
            self.progress_title.setText("Scan Telemetry Status: RUNNING...")
            self.current_file_label.setText(f"Initializing scan on {self.scan_target}...")
            self.empty_label.setText("Analyzing files...")
            self.empty_label.setStyleSheet("color: #94A3B8; font-size: 13px; font-weight: bold;")
            self.empty_label.show()
            self._update_table_view_height()

            # Start background worker
            self.scanner = BackgroundScanner(self.scan_target, recursive=True, db_manager=self.db)
            self.scanner.progress_updated.connect(self._on_progress_updated)
            self.scanner.scan_completed.connect(self._on_scan_completed)
            self.scanner.scan_error.connect(self._on_scan_error)
            self.scanner.start()

    def _cancel_scan(self):
        if self.scan_mode == "IMAGE_TEXT":
            if self.image_worker:
                self.image_worker.cancel()
                self.image_worker.wait()
                self._reset_ui_idle()
                self.progress_title.setText("Image Analysis Status: CANCELLED")
        else:
            if self.scanner:
                self.scanner.stop()
                self.scanner.wait()
                self._reset_ui_idle()
                self.progress_title.setText("Scan Telemetry Status: CANCELLED")
                if self.table_model.rowCount() == 0:
                    self._set_ui_state("TARGET_SELECTED" if self.scan_target else "INITIAL")
                    self.progress_card.setVisible(True)
                else:
                    self._set_ui_state("COMPLETED")

    def _on_image_progress_updated(self, stage_name: str, percent: int):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(percent)
        self.progress_title.setText(f"Image Analysis Status: {stage_name} ({percent}%)")
        self.current_file_label.setText(f"Target: {self.scan_target}")

    def _on_image_scan_completed(self, result: Dict[str, Any]):
        self._reset_ui_idle()
        self.current_ui_state = "COMPLETED"
        self.current_image_result = result
        if hasattr(self, "empty_state_container"):
            self.empty_state_container.setVisible(False)

        cat = result.get("category", "UNABLE TO DETERMINE")
        self.progress_title.setText(f"Image Analysis Complete in {result.get('duration_sec', 0)}s — Category: {cat}")
        self.current_file_label.setText("Image text & steganography analysis completed successfully.")

        self._show_image_result_card(result)

    def _show_image_result_card(self, result: Dict[str, Any]):
        self.single_card.setVisible(True)
        cat = result.get("category", "UNABLE TO DETERMINE")

        if "HIDDEN" in cat:
            badge_style = "background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #F59E0B;"
        elif "EMBEDDED" in cat:
            badge_style = "background-color: rgba(56, 189, 248, 0.2); color: #38BDF8; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #38BDF8;"
        else:
            badge_style = "background-color: rgba(34, 197, 94, 0.2); color: #22C55E; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #22C55E;"

        self.single_title.setText("🖼️ IMAGE HIDDEN TEXT FINDER RESULTS")
        self.single_verdict_badge.setText(f"CATEGORY: {cat}")
        self.single_verdict_badge.setStyleSheet(badge_style)
        self.single_risk_badge.setText("Risk: - (Finding)")
        self.single_source_badge.setText("Source: Scan Center (Image Hidden Text)")

        self.btn_investigate.setText("🔍 View Detailed Report →")
        self.btn_investigate.setVisible(True)
        try:
            self.btn_investigate.clicked.disconnect()
        except Exception:
            pass
        self.btn_investigate.clicked.connect(self._on_view_image_details_clicked)

        self.val_filename.setText(result.get("filename", "-"))
        self.val_path.setText(result.get("file_path", "-"))
        self.val_size.setText(f"{result.get('file_size', 0):,} bytes")
        self.val_type.setText(f"{result.get('file_format', '-')} ({result.get('dimensions', '-')})")
        self.val_verdict.setText(cat)
        self.val_risk.setText("N/A (Analysis Finding)")
        self.val_source.setText("Scan Center (Image Hidden Text)")
        self.val_rule.setText(result.get("detection_method", "Image Pipeline"))
        self.val_sha256.setText(result.get("sha256", "N/A"))

        reason_str = (
            f"<b>Visible Text</b>: {result.get('visible_text', 'None')}<br>"
            f"<b>Hidden Text</b>: {result.get('hidden_text', 'None')}"
        )
        self.val_reason.setText(reason_str)

        evidence_content = (
            f"=== VISIBLE TEXT ===\n{result.get('visible_text')}\n\n"
            f"=== HIDDEN / CONCEALED TEXT ===\n{result.get('hidden_text')}\n\n"
            f"=== METHODOLOGY ===\n{result.get('detection_method')}\n\n"
            f"=== SECURITY INTERPRETATION ===\n{result.get('security_interpretation')}"
        )
        self.single_evidence_view.setPlainText(evidence_content)

    def _on_view_image_details_clicked(self):
        if self.current_image_result:
            dlg = ImageAnalysisDetailsDialog(self.current_image_result, parent=self)
            dlg.exec()

    def _on_progress_updated(self, file_path, files_scanned, threats_found):
        # Update progress details
        self.progress_bar.setRange(0, 0)
        self.progress_title.setText(f"Scan Status: Scanning... Scanned: {files_scanned} | Threats Found: {threats_found}")
        self.current_file_label.setText(file_path)

    def _on_table_row_clicked(self, index):
        """Displays inspection card for clicked result record."""
        rec = self.table_model.get_record_at(index.row())
        if not rec:
            return
        self._show_inspection_card(rec)

    def _on_table_row_double_clicked(self, index):
        rec = self.table_model.get_record_at(index.row())
        if rec:
            self._show_inspection_card(rec)
            if rec.get("verdict") in ("SUSPICIOUS", "MALICIOUS"):
                self._on_investigate_clicked()

    def _show_inspection_card(self, rec: Dict[str, Any]):
        """Renders authentic evidence and static indicators for the selected file."""
        if not rec:
            return
        self.current_record = rec
        self.single_card.setVisible(True)
        self.current_ui_state = "COMPLETED"
        if hasattr(self, "empty_state_container"):
            self.empty_state_container.setVisible(False)
        if hasattr(self, "table_view"):
            self.table_view.setVisible(True)

        verdict = str(rec.get("verdict", "UNKNOWN")).upper()
        threat_name = rec.get("threat_name", "Security Threat")
        for suffix in [" (Existing File Scan)", " (Scan Center)"]:
            if threat_name.endswith(suffix):
                threat_name = threat_name[:-len(suffix)]

        # 1. Verdict badge styling
        if verdict == "CLEAN":
            badge_style = "background-color: rgba(34, 197, 94, 0.15); color: #22C55E; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(34, 197, 94, 0.35);"
            border_color = "#22C55E"
            val_verdict_style = "color: #22C55E; font-size: 11px; font-weight: bold;"
        elif verdict == "SUSPICIOUS":
            badge_style = "background-color: rgba(245, 158, 11, 0.15); color: #F59E0B; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(245, 158, 11, 0.35);"
            border_color = "#F59E0B"
            val_verdict_style = "color: #F59E0B; font-size: 11px; font-weight: bold;"
        elif verdict == "MALICIOUS":
            badge_style = "background-color: rgba(239, 68, 68, 0.2); color: #EF4444; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #EF4444;"
            border_color = "#EF4444"
            val_verdict_style = "color: #EF4444; font-size: 11px; font-weight: bold;"
        else:
            badge_style = "background-color: #1F2937; color: #9CA3AF; font-weight: bold; font-size: 11px; padding: 3px 8px; border-radius: 4px; border: 1px solid #374151;"
            border_color = "#374151"
            val_verdict_style = "color: #9CA3AF; font-size: 11px; font-weight: bold;"

        self.single_verdict_badge.setText(f"VERDICT: {verdict}")
        self.single_verdict_badge.setStyleSheet(badge_style)

        # 2. Risk Score & Source Badges
        risk = rec.get("risk_score")
        if risk is None or verdict == "CLEAN":
            risk = 0
        self.single_risk_badge.setText(f"Risk Score: {risk} / 100")
        source = rec.get("detection_source") or "Scan Center"
        self.single_source_badge.setText(f"Source: {source}")

        # 3. Investigate Action Button (Only for threats: SUSPICIOUS or MALICIOUS)
        is_threat = verdict in ("SUSPICIOUS", "MALICIOUS")
        self.btn_investigate.setVisible(is_threat)
        self.btn_investigate.setEnabled(is_threat)

        # 4. Telemetry Grid Values
        fn = rec.get("filename") or (os.path.basename(rec.get("file_path", "")) if rec.get("file_path") else "Unknown")
        fp = rec.get("file_path") or rec.get("full_path") or "Not available"
        raw_size = rec.get("file_size")
        size_str = format_file_size(raw_size)
        if isinstance(raw_size, (int, float)) and raw_size >= 0:
            size_str += f" ({int(raw_size):,} bytes)"
        ft = rec.get("file_type") or "Unknown"
        sha = rec.get("sha256") or "Not available"

        # Extract Detection Rule from static_indicators or record
        rules = [si.get("rule_name") for si in rec.get("static_indicators", []) if si.get("rule_name")]
        if rules:
            rule_str = ", ".join(dict.fromkeys(rules))
        elif rec.get("rule_name"):
            rule_str = str(rec.get("rule_name"))
        elif is_threat:
            rule_str = "HEURISTIC_DETECTION"
        else:
            rule_str = "None (Clean)"

        self.val_filename.setText(fn)
        self.val_filename.setToolTip(fn)
        self.val_path.setText(fp)
        self.val_path.setToolTip(fp)
        self.val_size.setText(size_str)
        self.val_type.setText(ft)
        self.val_verdict.setText(verdict)
        self.val_verdict.setStyleSheet(val_verdict_style)
        self.val_risk.setText(f"{risk} / 100")
        self.val_source.setText(source)
        self.val_rule.setText(rule_str)
        self.val_sha256.setText(sha)
        self.val_sha256.setToolTip(sha)

        # 5. Detection Reason Banner
        reason = rec.get("reason") or ("No security threat detected." if verdict == "CLEAN" else "Suspicious indicator flagged.")
        self.reason_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-left: 3px solid {border_color};
                border-radius: 4px;
                padding: 5px 8px;
            }}
        """)
        self.val_reason.setText(f"<b>Detection Reason:</b> {reason}")

        # 6. Detection Evidence List
        evidence_items = rec.get("evidence_list") or []
        if not evidence_items and rec.get("reason"):
            evidence_items = [rec.get("reason")]
        evidence_text = "\n".join([f"• {e}" for e in evidence_items]) if evidence_items else "• No suspicious indicators detected."
        self.single_evidence_view.setText(evidence_text)
        self._update_evidence_height()

    def _on_investigate_clicked(self):
        if not hasattr(self, "current_record") or not self.current_record:
            return
        inc_id = self._find_or_create_incident(self.current_record)
        if inc_id:
            self.investigate_incident.emit(inc_id)

    def _find_or_create_incident(self, rec: Dict[str, Any]) -> Optional[int]:
        if rec.get("incident_id"):
            return rec["incident_id"]

        path = rec.get("file_path") or rec.get("full_path")
        sha = rec.get("sha256")
        
        # 1. Search existing incident by path or SHA-256 to prevent duplicates
        existing = self.inc_repo.get_active_incident_by_path_or_hash(path, sha)
        if existing:
            inc_id = existing["id"]
            rec["incident_id"] = inc_id
            return inc_id

        verdict = str(rec.get("verdict", "UNKNOWN")).upper()
        if verdict in ("SUSPICIOUS", "MALICIOUS"):
            threat_name = rec.get("threat_name") or "Security Threat"
            reason = rec.get("reason") or "Detected via Scan Center"
            folder = os.path.dirname(path) if path else ""
            ev_list = rec.get("evidence_list") or []
            if not ev_list and reason:
                ev_list = [reason]

            rule_name = rec.get("rule_name") or ("RANSOM_NOTE_PATTERN" if "note" in reason.lower() or "readme" in reason.lower() else "STATIC_HEURISTIC_RULE")
            evidence_str = (
                f"Detection Source: Scan Center\n"
                f"Detection Rule: {rule_name}\n"
                f"Observed Reason: {reason}\n" +
                "\n".join([f"• {e}" for e in ev_list])
            )

            new_id = self.inc_repo.insert_incident(
                threat_name=f"{threat_name} (Scan Center)",
                severity=rec.get("severity", "LOW"),
                risk_score=rec.get("risk_score", 30),
                affected_folder=folder,
                affected_file=rec.get("filename") or (os.path.basename(path) if path else "file"),
                full_path=path or "Unknown",
                detection_reason=f"[Scan Center] {reason}",
                recommendation="Inspect file location and signature. Quarantine or remove if unrecognized.",
                status="ACTIVE",
                verdict=verdict,
                evidence=evidence_str,
                attribution_status="UNAVAILABLE",
                file_size=rec.get("file_size"),
                sha256=rec.get("sha256"),
                file_type=rec.get("file_type"),
                detection_source="Scan Center"
            )
            rec["incident_id"] = new_id
            return new_id
        return None

    def _on_scan_completed(self, results):
        self._reset_ui_idle()
        self.current_ui_state = "COMPLETED"
        if hasattr(self, "empty_state_container"):
            self.empty_state_container.setVisible(False)
        if hasattr(self, "table_view"):
            self.table_view.setVisible(True)

        is_single = results.get("is_single_file", False)
        single_res = results.get("single_file_result")

        # 1. Single File Scan Presentation
        if is_single and single_res:
            self._show_inspection_card(single_res)
            self.table_model.set_records([single_res])
        else:
            # 2. Folder Scan Presentation
            self.single_card.setVisible(False)
            threats = results.get("detected_threats", [])
            self.table_model.set_records(threats)
            if threats:
                self._show_inspection_card(threats[0])

        # Display completion summary
        duration = results["duration_sec"]
        clean_c = results.get("clean_count", 0)
        sus_c = results.get("suspicious_count", 0)
        mal_c = results.get("malicious_count", 0)
        unk_c = results.get("unknown_count", 0)
        
        msg = (
            f"Scan Complete in {duration}s: {results['files_scanned']} Scanned | "
            f"Clean: {clean_c} | Suspicious: {sus_c} | Malicious: {mal_c} | Unknown: {unk_c}"
        )
        self.progress_title.setText(msg)
        self.current_file_label.setText("Scan telemetry processing completed successfully.")
        
        self._update_table_view_height()
        self._adjust_table_columns()
        self._update_empty_state()

    def _on_scan_error(self, err_msg):
        self._reset_ui_idle()
        self.progress_title.setText(f"Scan Telemetry Status: ERROR - {err_msg}")
        self._update_table_view_height()
        self._update_empty_state()

    def _reset_ui_idle(self):
        self.start_scan_btn.setEnabled(bool(self.scan_target))
        self.select_folder_btn.setEnabled(True)
        self.select_file_btn.setEnabled(True)
        self.cancel_scan_btn.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)

    def _update_empty_state(self):
        if self.table_model.rowCount() > 0:
            self.current_ui_state = "COMPLETED"

        if self.current_ui_state in ("INITIAL", "TARGET_SELECTED"):
            if hasattr(self, "empty_state_container"):
                self.empty_state_container.setVisible(True)
            self.table_view.setVisible(False)
            self.empty_label.hide()
            return

        if hasattr(self, "empty_state_container"):
            self.empty_state_container.setVisible(False)
        self.table_view.setVisible(True)
        if self.table_model.rowCount() == 0:
            self.empty_label.setText("No security threats detected. All scanned files clean.")
            self.empty_label.setStyleSheet("color: #22C55E; font-size: 13px; font-weight: bold;")
            self.empty_label.show()
        else:
            self.empty_label.hide()

    def _update_evidence_height(self):
        """Dynamically computes and sets evidence text area height so that no internal scrollbar exists."""
        if not hasattr(self, "single_evidence_view") or not self.single_card.isVisible():
            return
        doc = self.single_evidence_view.document()
        vp_width = self.single_evidence_view.viewport().width()
        if vp_width > 50:
            doc.setTextWidth(vp_width)
        doc_h = int(doc.size().height())
        target_h = max(70, doc_h + 16)
        self.single_evidence_view.setFixedHeight(target_h)

    def _update_table_view_height(self):
        """Dynamically sizes the Scan Results table so it expands naturally without tiny cramped scroll areas."""
        if not hasattr(self, "table_model") or not hasattr(self, "table_view"):
            return
        rows = self.table_model.rowCount()
        if rows == 0:
            target_h = 140
        else:
            # 36px header + 36px per row + 8px frame padding
            needed = 36 + (rows * 36) + 8
            # Cap at 500px for large datasets to keep UX fluid, otherwise expand fully
            target_h = max(180, min(500, needed))
        self.table_view.setFixedHeight(target_h)

    def _adjust_table_columns(self):
        """Proportionally distributes table columns across available viewport width to eliminate horizontal scroll."""
        if not hasattr(self, "table_view"):
            return
        total_w = self.table_view.viewport().width()
        if total_w < 300:
            return
        # Columns:
        # 0: File Name (18%)
        # 1: Verdict (11%)
        # 2: Reason / Evidence (33%)
        # 3: SHA-256 (16%)
        # 4: File Type (12%)
        # 5: Size (remaining ~10%)
        c0 = max(130, int(total_w * 0.18))
        c1 = max(80, int(total_w * 0.11))
        c2 = max(200, int(total_w * 0.33))
        c3 = max(120, int(total_w * 0.16))
        c4 = max(90, int(total_w * 0.12))
        c5 = max(70, total_w - (c0 + c1 + c2 + c3 + c4))

        self.table_view.setColumnWidth(0, c0)
        self.table_view.setColumnWidth(1, c1)
        self.table_view.setColumnWidth(2, c2)
        self.table_view.setColumnWidth(3, c3)
        self.table_view.setColumnWidth(4, c4)
        self.table_view.setColumnWidth(5, c5)

    def resizeEvent(self, event):
        super(ScanPage, self).resizeEvent(event)
        self._update_evidence_height()
        self._adjust_table_columns()

    def showEvent(self, event):
        super(ScanPage, self).showEvent(event)
        self._update_evidence_height()
        self._adjust_table_columns()
        self._update_table_view_height()

    def eventFilter(self, obj, event):
        if obj == self.table_view and event.type() == QEvent.Resize:
            w = self.table_view.viewport().width()
            h = self.table_view.viewport().height()
            self.empty_label.setGeometry(0, 0, w, h)
            self._adjust_table_columns()
        return super(ScanPage, self).eventFilter(obj, event)
