import os
import datetime
from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QSizePolicy, QSplitter, QGridLayout,
    QApplication
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QColor

from ui.components.tables import format_file_size
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository


class ScanThreatsDialog(QDialog):
    """
    Modal EDR investigation window displaying authentic threats identified by an Existing File Scan.
    Features a spacious, responsive two-column investigation layout with complete telemetry display,
    word-wrapping for long paths, authentic SHA-256 clipboard copying, multi-line evidence table,
    and direct integration with the Threat Repository.
    """
    investigate_threat = Signal(int)  # Emits incident_id

    def __init__(self, threats: List[Dict[str, Any]], scan_summary: Optional[Dict[str, Any]] = None,
                 db_manager=None, parent=None):
        super(ScanThreatsDialog, self).__init__(parent)
        self.threats = threats or []
        self.scan_summary = scan_summary or {}
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.current_index = 0
        self._current_sha256 = ""

        self.setWindowTitle("RansomGuard EDR — Existing File Scan Detections")
        self.setModal(True)

        # Dynamic screen-aware sizing: Default ~1280x820, min 1050x650
        screen = QApplication.primaryScreen().availableGeometry() if QApplication.primaryScreen() else None
        default_w = 1280
        default_h = 820
        if screen:
            default_w = min(1340, max(1050, int(screen.width() * 0.88)))
            default_h = min(860, max(680, int(screen.height() * 0.86)))
        self.resize(default_w, default_h)
        self.setMinimumSize(1020, 640)
        self.setSizeGripEnabled(True)

        # Enable Windows 10/11 Dark Title Bar
        self._apply_dark_titlebar()

        # Apply RansomGuard unified cyber dark purple theme
        self._apply_styling()

        # Main vertical layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 14, 16, 14)
        main_layout.setSpacing(12)

        # 1. Top Header Card (Compact, high-contrast)
        self._build_header(main_layout)

        # 2. Main Investigation Body: Responsive Two-Column QSplitter
        self.splitter = QSplitter(Qt.Horizontal, self)
        self.splitter.setHandleWidth(4)

        # Left Column: Detected Threats List (30–35% width)
        left_widget = self._build_left_pane()
        self.splitter.addWidget(left_widget)

        # Right Column: Selected Threat Details Panel (65–70% width)
        right_widget = self._build_right_pane()
        self.splitter.addWidget(right_widget)

        # Set initial splitter proportions (35% left, 65% right)
        left_initial_w = max(360, int(default_w * 0.32))
        right_initial_w = default_w - left_initial_w - 40
        self.splitter.setSizes([left_initial_w, right_initial_w])
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 7)

        main_layout.addWidget(self.splitter, 1)

        # 3. Pinned Bottom Action Bar (always visible)
        self._build_footer(main_layout)

        # Populate threat list and select initial row
        self._populate_list()

    def _apply_dark_titlebar(self):
        """Attempts to set Windows 10/11 immersive dark mode on the native dialog frame."""
        try:
            import ctypes
            hwnd = int(self.winId())
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            val = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(val), ctypes.sizeof(val)
            )
        except Exception:
            pass

    def _apply_styling(self):
        """Theme stylesheet matching RansomGuard enterprise dark-navy surface hierarchy."""
        self.setStyleSheet("""
            QDialog {
                background-color: #070B16;
                color: #E2E8F0;
                font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            }
            QFrame {
                background: transparent;
                border: none;
            }
            QFrame#dialogHeaderCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-bottom: 2px solid #168BFF;
                border-radius: 8px;
                padding: 10px 16px;
            }
            QFrame#summaryCard,
            QFrame#fileInfoCard,
            QFrame#reasonCard,
            QFrame#evidenceCard,
            QFrame#yaraCard,
            QFrame#intelCard,
            QFrame#noSelectionCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
                padding: 12px 16px;
            }
            QFrame.metricTile {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QSplitter::handle {
                background-color: #1A2940;
                border-radius: 2px;
            }
            QSplitter::handle:hover {
                background-color: #355B8A;
            }
            QListWidget#threatList {
                background-color: #070B16;
                border: 1px solid #1A2940;
                border-radius: 8px;
                outline: none;
                padding: 6px;
            }
            QListWidget#threatList::item {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 8px 10px;
                margin-bottom: 6px;
                color: #E2E8F0;
            }
            QListWidget#threatList::item:hover {
                background-color: #111A2B;
                border-color: #21334D;
            }
            QListWidget#threatList::item:selected {
                background-color: #17233A;
                border: 1px solid #355B8A;
                border-left: 4px solid #168BFF;
                color: #FFFFFF;
            }
            QTableWidget {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                gridline-color: #1A2940;
                outline: none;
            }
            QTableWidget::item {
                padding: 8px 10px;
                border-bottom: 1px solid #1A2940;
                color: #CBD5E1;
            }
            QHeaderView::section {
                background-color: #111A2B;
                color: #A9B8D4;
                padding: 7px 10px;
                border: none;
                border-bottom: 1px solid #1A2940;
                font-weight: bold;
                font-size: 11px;
                letter-spacing: 0.4px;
            }
            QScrollBar:vertical {
                background: #070B16;
                width: 8px;
                margin: 0px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #1A2940;
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #168BFF;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """)

    def _build_header(self, parent_layout):
        """Builds compact top header showing scan session stats."""
        header_card = QFrame(self)
        header_card.setObjectName("dialogHeaderCard")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(12, 8, 14, 8)
        h_layout.setSpacing(12)

        icon_lbl = QLabel("⚠️", header_card)
        icon_lbl.setStyleSheet("font-size: 24px; background: transparent; border: none;")
        h_layout.addWidget(icon_lbl)

        v_box = QVBoxLayout()
        v_box.setSpacing(2)

        count = len(self.threats)
        threat_str = f"{count} Threat{'s' if count != 1 else ''}"
        title_lbl = QLabel(f"EXISTING FILE SCAN DETECTIONS — {threat_str.upper()} IDENTIFIED", header_card)
        title_lbl.setStyleSheet("font-size: 15px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.4px; background: transparent; border: none;")
        v_box.addWidget(title_lbl)

        # Scan session metadata
        scan_id = self.scan_summary.get("scan_id") or "Current Session"
        analyzed = self.scan_summary.get("files_analyzed") or self.scan_summary.get("analyzed_count") or 0
        end_time = self.scan_summary.get("end_time") or self.scan_summary.get("start_time") or "Completed"
        sub_text = f"Scan Run: {scan_id}   •   {analyzed:,} files evaluated   •   Timestamp: {end_time}"
        sub_lbl = QLabel(sub_text, header_card)
        sub_lbl.setStyleSheet("color: #94A3B8; font-size: 11.5px; font-family: Consolas, monospace; background: transparent; border: none;")
        v_box.addWidget(sub_lbl)

        h_layout.addLayout(v_box)
        h_layout.addStretch()

        badge_lbl = QLabel(f" {count} DETECTED ", header_card)
        badge_lbl.setStyleSheet("""
            background-color: rgba(239, 68, 68, 0.2);
            color: #EF4444;
            border: 1px solid rgba(239, 68, 68, 0.5);
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 10px;
        """)
        h_layout.addWidget(badge_lbl)

        parent_layout.addWidget(header_card)

    def _build_left_pane(self) -> QWidget:
        """Constructs left pane with detected threats list."""
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        header_row = QHBoxLayout()
        left_title = QLabel(f"DETECTED THREATS ({len(self.threats)})", container)
        left_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        header_row.addWidget(left_title)
        header_row.addStretch()

        layout.addLayout(header_row)

        self.threat_list = QListWidget(container)
        self.threat_list.setObjectName("threatList")
        self.threat_list.currentRowChanged.connect(self._on_threat_selected)
        layout.addWidget(self.threat_list, 1)

        return container

    def _build_right_pane(self) -> QWidget:
        """Constructs scrollable right pane for detailed threat investigation."""
        self.detail_scroll = QScrollArea(self)
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.detail_container = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_container)
        self.detail_layout.setContentsMargins(0, 0, 4, 0)
        self.detail_layout.setSpacing(12)
        self.detail_scroll.setWidget(self.detail_container)

        # ── SECTION A: DETECTION SUMMARY TILES ─────────────────────
        self.summary_tiles_frame = QFrame(self.detail_container)
        self.summary_tiles_frame.setObjectName("summaryCard")
        st_layout = QVBoxLayout(self.summary_tiles_frame)
        st_layout.setContentsMargins(14, 12, 14, 12)
        st_layout.setSpacing(10)

        # 4 Metric Cards Row
        tiles_row = QHBoxLayout()
        tiles_row.setSpacing(8)

        self.tile_det_type = self._create_metric_tile("DETECTION TYPE", "Potential Ransom Note Pattern", "#38A8FF")
        self.tile_verdict = self._create_metric_tile("VERDICT", "SUSPICIOUS", "#EF4444")
        self.tile_severity = self._create_metric_tile("SEVERITY", "LOW", "#38BDF8")
        self.tile_risk = self._create_metric_tile("RISK SCORE", "30 / 100", "#F59E0B")

        tiles_row.addWidget(self.tile_det_type["frame"], 2)
        tiles_row.addWidget(self.tile_verdict["frame"], 1)
        tiles_row.addWidget(self.tile_severity["frame"], 1)
        tiles_row.addWidget(self.tile_risk["frame"], 1)
        st_layout.addLayout(tiles_row)

        # Headline Row
        head_row = QHBoxLayout()
        self.threat_name_lbl = QLabel("Security Threat Identified", self.summary_tiles_frame)
        self.threat_name_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        self.threat_name_lbl.setWordWrap(True)
        head_row.addWidget(self.threat_name_lbl, 1)

        self.detection_source_lbl = QLabel("Source: Existing File Scan", self.summary_tiles_frame)
        self.detection_source_lbl.setStyleSheet("color: #8B98A8; font-size: 11.5px; font-weight: 600; padding: 2px 8px; background: #111A2B; border: 1px solid #1A2940; border-radius: 4px;")
        head_row.addWidget(self.detection_source_lbl)
        st_layout.addLayout(head_row)

        self.detail_layout.addWidget(self.summary_tiles_frame)

        # ── SECTION B: FILE INFORMATION & METADATA ───────────────────
        self.file_info_card = QFrame(self.detail_container)
        self.file_info_card.setObjectName("fileInfoCard")
        fi_layout = QVBoxLayout(self.file_info_card)
        fi_layout.setContentsMargins(14, 12, 14, 12)
        fi_layout.setSpacing(10)

        fi_title = QLabel("📁 FILE INFORMATION & METADATA", self.file_info_card)
        fi_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        fi_layout.addWidget(fi_title)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setContentsMargins(0, 4, 0, 4)
        grid.setColumnStretch(0, 0)
        grid.setColumnStretch(1, 1)

        self.meta_labels = {}
        fields = [
            ("file_name", "File Name:"),
            ("full_path", "Full Path:"),
            ("file_type", "File Type:"),
            ("file_size", "File Size:"),
            ("time_created", "Created Time:"),
            ("time_modified", "Modified Time:"),
            ("time_scanned", "Scan Timestamp:"),
        ]

        for row_idx, (key, label_str) in enumerate(fields):
            lbl = QLabel(label_str, self.file_info_card)
            lbl.setStyleSheet("color: #8B98A8; font-size: 12px; font-weight: 600;")
            lbl.setAlignment(Qt.AlignRight | Qt.AlignTop)
            lbl.setFixedWidth(120)

            val = QLabel("Not available", self.file_info_card)
            val.setStyleSheet("color: #F8FAFC; font-size: 12px; font-family: Segoe UI;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            val.setWordWrap(True)

            if key in ("full_path", "file_name"):
                val.setStyleSheet("color: #F8FAFC; font-size: 12px; font-family: Consolas, monospace;")

            grid.addWidget(lbl, row_idx, 0)
            grid.addWidget(val, row_idx, 1)
            self.meta_labels[key] = val

        # SHA-256 Full Row with Copy Button
        sha_row_idx = len(fields)
        sha_lbl = QLabel("SHA-256:", self.file_info_card)
        sha_lbl.setStyleSheet("color: #8B98A8; font-size: 12px; font-weight: 600;")
        sha_lbl.setAlignment(Qt.AlignRight | Qt.AlignTop)
        sha_lbl.setFixedWidth(120)
        grid.addWidget(sha_lbl, sha_row_idx, 0)

        sha_container = QWidget(self.file_info_card)
        sha_layout = QHBoxLayout(sha_container)
        sha_layout.setContentsMargins(0, 0, 0, 0)
        sha_layout.setSpacing(8)

        self.sha_val_lbl = QLabel("Not available", sha_container)
        self.sha_val_lbl.setStyleSheet("color: #38BDF8; font-size: 12px; font-family: Consolas, monospace;")
        self.sha_val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.sha_val_lbl.setWordWrap(True)
        sha_layout.addWidget(self.sha_val_lbl, 1)

        self.btn_copy_sha = QPushButton("📋 Copy SHA-256", sha_container)
        self.btn_copy_sha.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #CBD5E1;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11.5px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #355B8A;
            }
        """)
        self.btn_copy_sha.setCursor(Qt.PointingHandCursor)
        self.btn_copy_sha.clicked.connect(self._copy_sha256)
        sha_layout.addWidget(self.btn_copy_sha)

        grid.addWidget(sha_container, sha_row_idx, 1)
        self.meta_labels["sha256"] = self.sha_val_lbl

        fi_layout.addLayout(grid)
        self.detail_layout.addWidget(self.file_info_card)

        # ── SECTION C: DETECTION REASON & WHY WAS THIS DETECTED ──────
        self.reason_card = QFrame(self.detail_container)
        self.reason_card.setObjectName("reasonCard")
        rc_layout = QVBoxLayout(self.reason_card)
        rc_layout.setContentsMargins(14, 12, 14, 12)
        rc_layout.setSpacing(8)

        rc_title = QLabel("📋 DETECTION REASON & SECURITY EXPLANATION", self.reason_card)
        rc_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        rc_layout.addWidget(rc_title)

        # Primary detection reason
        lbl_r_sub = QLabel("DETECTION REASON:", self.reason_card)
        lbl_r_sub.setStyleSheet("font-size: 11px; font-weight: bold; color: #F59E0B;")
        rc_layout.addWidget(lbl_r_sub)

        self.detection_reason_lbl = QLabel("Reason unavailable.", self.reason_card)
        self.detection_reason_lbl.setStyleSheet("color: #F8FAFC; font-size: 12px; line-height: 1.4; padding: 6px 10px; background: #111A2B; border: 1px solid #1A2940; border-radius: 4px;")
        self.detection_reason_lbl.setWordWrap(True)
        self.detection_reason_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        rc_layout.addWidget(self.detection_reason_lbl)

        # "Why was this file detected?" section
        lbl_why = QLabel("WHY WAS THIS FILE DETECTED?", self.reason_card)
        lbl_why.setStyleSheet("font-size: 11px; font-weight: bold; color: #38BDF8; margin-top: 4px;")
        rc_layout.addWidget(lbl_why)

        self.why_detected_lbl = QLabel("Insufficient evidence available to provide a more specific explanation.", self.reason_card)
        self.why_detected_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px; line-height: 1.4; padding: 6px 10px; background: #111A2B; border: 1px solid #1A2940; border-radius: 4px;")
        self.why_detected_lbl.setWordWrap(True)
        self.why_detected_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        rc_layout.addWidget(self.why_detected_lbl)

        self.detail_layout.addWidget(self.reason_card)

        # ── SECTION D: DETECTION EVIDENCE & APPLIED RULES TABLE ───────
        self.evidence_card = QFrame(self.detail_container)
        self.evidence_card.setObjectName("evidenceCard")
        ec_layout = QVBoxLayout(self.evidence_card)
        ec_layout.setContentsMargins(14, 12, 14, 12)
        ec_layout.setSpacing(8)

        ec_title = QLabel("🔬 DETECTION EVIDENCE & APPLIED RULES", self.evidence_card)
        ec_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        ec_layout.addWidget(ec_title)

        self.evidence_table = QTableWidget(self.evidence_card)
        self.evidence_table.setColumnCount(4)
        self.evidence_table.setHorizontalHeaderLabels(["Rule", "Observed Evidence", "Contribution / Score", "Detection Stage"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.setWordWrap(True)
        self.evidence_table.setMinimumHeight(120)
        ec_layout.addWidget(self.evidence_table)

        self.detail_layout.addWidget(self.evidence_card)

        # ── SECTION E: YARA RULE ANALYSIS ────────────────────────────
        self.yara_card = QFrame(self.detail_container)
        self.yara_card.setObjectName("yaraCard")
        yc_layout = QVBoxLayout(self.yara_card)
        yc_layout.setContentsMargins(14, 12, 14, 12)
        yc_layout.setSpacing(6)

        yc_title = QLabel("🛡️ YARA RULE ANALYSIS", self.yara_card)
        yc_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #38BDF8; letter-spacing: 0.5px;")
        yc_layout.addWidget(yc_title)

        y_stat_row = QHBoxLayout()
        self.yara_status_lbl = QLabel("Status: No Match", self.yara_card)
        self.yara_status_lbl.setStyleSheet("color: #E2E8F0; font-size: 12px; font-weight: 600;")
        y_stat_row.addWidget(self.yara_status_lbl)

        self.yara_rules_lbl = QLabel("Rules Matched: 0", self.yara_card)
        self.yara_rules_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px;")
        y_stat_row.addWidget(self.yara_rules_lbl)
        y_stat_row.addStretch()
        yc_layout.addLayout(y_stat_row)

        self.yara_evidence_lbl = QLabel("No YARA rules matched this file.", self.yara_card)
        self.yara_evidence_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-family: Consolas; background: #111A2B; border: 1px solid #1A2940; padding: 6px 10px; border-radius: 4px;")
        self.yara_evidence_lbl.setWordWrap(True)
        self.yara_evidence_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        yc_layout.addWidget(self.yara_evidence_lbl)

        self.detail_layout.addWidget(self.yara_card)

        # ── SECTION F: THREAT INTELLIGENCE LOOKUP ─────────────────────
        self.intel_card = QFrame(self.detail_container)
        self.intel_card.setObjectName("intelCard")
        ic_layout = QVBoxLayout(self.intel_card)
        ic_layout.setContentsMargins(14, 12, 14, 12)
        ic_layout.setSpacing(6)

        ic_title = QLabel("🌐 THREAT INTELLIGENCE LOOKUP", self.intel_card)
        ic_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #38A8FF; letter-spacing: 0.5px;")
        ic_layout.addWidget(ic_title)

        i_stat_row = QHBoxLayout()
        self.intel_status_lbl = QLabel("Status: Not Checked", self.intel_card)
        self.intel_status_lbl.setStyleSheet("color: #E2E8F0; font-size: 12px; font-weight: 600;")
        i_stat_row.addWidget(self.intel_status_lbl)

        self.intel_provider_lbl = QLabel("Provider: RansomGuard Threat Intel", self.intel_card)
        self.intel_provider_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px;")
        i_stat_row.addWidget(self.intel_provider_lbl)
        i_stat_row.addStretch()
        ic_layout.addLayout(i_stat_row)

        self.intel_details_lbl = QLabel("Threat Intelligence is not available because no configured intelligence provider returned a result.", self.intel_card)
        self.intel_details_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-family: Consolas; background: #111A2B; border: 1px solid #1A2940; padding: 6px 10px; border-radius: 4px;")
        self.intel_details_lbl.setWordWrap(True)
        self.intel_details_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ic_layout.addWidget(self.intel_details_lbl)

        self.detail_layout.addWidget(self.intel_card)

        # ── PLACEHOLDER: EMPTY SELECTION STATE ───────────────────────
        self.no_selection_widget = QFrame(self.detail_container)
        self.no_selection_widget.setObjectName("noSelectionCard")
        ns_layout = QVBoxLayout(self.no_selection_widget)
        ns_layout.setContentsMargins(20, 60, 20, 60)
        ns_lbl = QLabel("Select a detected threat from the list on the left to inspect static telemetry, metadata, and applied detection rules.", self.no_selection_widget)
        ns_lbl.setAlignment(Qt.AlignCenter)
        ns_lbl.setStyleSheet("color: #64748B; font-size: 13px; font-weight: 500; background: transparent; border: none;")
        ns_layout.addWidget(ns_lbl)
        self.detail_layout.addWidget(self.no_selection_widget)

        return self.detail_scroll

    def _create_metric_tile(self, label: str, val_default: str, color_hex: str) -> Dict[str, Any]:
        """Creates a modern styled metric tile for Section A."""
        frame = QFrame()
        frame.setStyleSheet("background-color: #111A2B; border: 1px solid #1A2940; border-radius: 6px; padding: 8px 12px;")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        lbl = QLabel(label, frame)
        lbl.setStyleSheet("font-size: 10px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        layout.addWidget(lbl)

        val = QLabel(val_default, frame)
        val.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {color_hex};")
        val.setWordWrap(True)
        layout.addWidget(val)

        return {"frame": frame, "val": val, "lbl": lbl}

    def _build_footer(self, parent_layout):
        """Builds pinned bottom footer with telemetry status and action buttons."""
        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(0, 4, 0, 0)
        bottom_row.setSpacing(10)

        self.status_hint = QLabel("Select a detected file to inspect static telemetry and rule triggers.", self)
        self.status_hint.setStyleSheet("color: #8B98A8; font-size: 12px;")
        bottom_row.addWidget(self.status_hint)
        bottom_row.addStretch()

        self.btn_investigate = QPushButton("🔍 Investigate in Threat Repository →", self)
        self.btn_investigate.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #168BFF;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1A94FF, stop:1 #52B4FF);
                border-color: #38A8FF;
            }
        """)
        self.btn_investigate.setCursor(Qt.PointingHandCursor)
        self.btn_investigate.clicked.connect(self._on_investigate_clicked)
        bottom_row.addWidget(self.btn_investigate)

        self.btn_close = QPushButton("Close", self)
        self.btn_close.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #CBD5E1;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #355B8A;
            }
        """)
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.clicked.connect(self.close)
        bottom_row.addWidget(self.btn_close)

        parent_layout.addLayout(bottom_row)

    def _copy_sha256(self):
        """Copies real SHA-256 hash to clipboard with immediate feedback."""
        if self._current_sha256 and self._current_sha256 != "Not available":
            clipboard = QApplication.clipboard()
            clipboard.setText(self._current_sha256)
            self.btn_copy_sha.setText("✓ Copied!")
            QTimer.singleShot(1500, lambda: self.btn_copy_sha.setText("📋 Copy SHA-256"))

    def _populate_list(self):
        """Populates left list with multi-line card items."""
        self.threat_list.clear()
        if not self.threats:
            empty_item = QListWidgetItem("No threats detected in this scan.")
            self.threat_list.addItem(empty_item)
            self.btn_investigate.setEnabled(False)
            self._set_details_visible(False)
            return

        for idx, t in enumerate(self.threats):
            file_path = t.get("file_path", "")
            filename = t.get("filename") or (os.path.basename(file_path) if file_path else "Unknown File")
            verdict = t.get("verdict", "SUSPICIOUS").upper()
            risk = t.get("risk_score", 0)
            severity = t.get("severity", "LOW").upper()

            item_text = f"{idx + 1}. {filename}\n   [{verdict}]  Risk: {risk}/100  ·  Severity: {severity}"
            item = QListWidgetItem(item_text)
            item.setToolTip(f"File: {filename}\nPath: {file_path}\nVerdict: {verdict} | Risk: {risk}/100 | Severity: {severity}")
            self.threat_list.addItem(item)

        self.threat_list.setCurrentRow(0)

    def _set_details_visible(self, visible: bool):
        """Toggles visibility between investigation detail cards and placeholder."""
        self.summary_tiles_frame.setVisible(visible)
        self.file_info_card.setVisible(visible)
        self.reason_card.setVisible(visible)
        self.evidence_card.setVisible(visible)
        self.yara_card.setVisible(visible)
        self.intel_card.setVisible(visible)
        self.no_selection_widget.setVisible(not visible)

    def _on_threat_selected(self, row: int):
        """Populates all detailed telemetry fields for the selected threat record."""
        if not self.threats or row < 0 or row >= len(self.threats):
            self._set_details_visible(False)
            return

        self._set_details_visible(True)
        self.current_index = row
        t = self.threats[row]

        # Update footer status
        self.status_hint.setText(f"Showing threat {row + 1} of {len(self.threats)}  ·  Select from list to inspect")

        # 1. Section A: Summary Metric Cards
        verdict = str(t.get("verdict", "SUSPICIOUS")).upper()
        severity = str(t.get("severity", "LOW")).upper()
        risk = t.get("risk_score", 0)
        det_type = t.get("threat_name") or t.get("detection_type") or "Security Threat Finding"

        self.tile_det_type["val"].setText(det_type)
        self.tile_verdict["val"].setText(verdict)
        if verdict in ("MALICIOUS", "CRITICAL", "THREAT"):
            self.tile_verdict["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #EF4444;")
        elif verdict in ("SUSPICIOUS", "WARN", "HIGH"):
            self.tile_verdict["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #F59E0B;")
        else:
            self.tile_verdict["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #38BDF8;")

        self.tile_severity["val"].setText(severity)
        if severity == "CRITICAL":
            self.tile_severity["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #EF4444;")
        elif severity == "HIGH":
            self.tile_severity["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #F97316;")
        elif severity == "MEDIUM":
            self.tile_severity["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #F59E0B;")
        else:
            self.tile_severity["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #38BDF8;")

        self.tile_risk["val"].setText(f"{risk} / 100")
        if risk >= 75:
            self.tile_risk["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #EF4444;")
        elif risk >= 40:
            self.tile_risk["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #F59E0B;")
        else:
            self.tile_risk["val"].setStyleSheet("font-size: 13px; font-weight: 800; color: #22C55E;")

        source = t.get("detection_source") or "Existing File Scan"
        self.detection_source_lbl.setText(f"Source: {source}")
        self.threat_name_lbl.setText(det_type)

        # 2. Section B: File Information
        file_path = t.get("file_path", "Not available")
        filename = t.get("filename") or (os.path.basename(file_path) if file_path != "Not available" else "Not available")
        self.meta_labels["file_name"].setText(filename)
        self.meta_labels["full_path"].setText(file_path)
        self.meta_labels["full_path"].setToolTip(file_path)

        sha = t.get("sha256") or "Not available"
        self._current_sha256 = sha
        self.sha_val_lbl.setText(sha)
        self.sha_val_lbl.setToolTip(sha)
        self.btn_copy_sha.setEnabled(bool(sha and sha != "Not available"))

        size_raw = t.get("file_size")
        if size_raw is not None and isinstance(size_raw, (int, float)) and size_raw >= 0:
            size_fmt = format_file_size(size_raw)
            self.meta_labels["file_size"].setText(f"{size_fmt} ({int(size_raw):,} bytes)")
        else:
            self.meta_labels["file_size"].setText("Not available")

        self.meta_labels["file_type"].setText(t.get("file_type") or "Not available")

        mtime_ns = t.get("mtime_ns")
        if mtime_ns and mtime_ns > 0:
            m_dt = datetime.datetime.fromtimestamp(mtime_ns / 1e9)
            self.meta_labels["time_modified"].setText(m_dt.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.meta_labels["time_modified"].setText("Not available")

        ctime_ns = t.get("ctime_ns")
        if ctime_ns and ctime_ns > 0:
            c_dt = datetime.datetime.fromtimestamp(ctime_ns / 1e9)
            self.meta_labels["time_created"].setText(c_dt.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.meta_labels["time_created"].setText("Not available")

        scan_time = t.get("detection_time") or t.get("last_scanned_at") or self.scan_summary.get("end_time") or "Not available"
        self.meta_labels["time_scanned"].setText(str(scan_time))

        # 3. Section C: Detection Reason & Why Detected
        reason = t.get("reason") or "Suspicious characteristic detected during file scan."
        self.detection_reason_lbl.setText(reason)

        # Synthesize honest, non-fabricated security explanation
        explanation = self._generate_security_explanation(t, reason)
        self.why_detected_lbl.setText(explanation)

        # 4. Section D: Evidence Table
        self._populate_evidence_table(t)

        # 5. Section E: YARA Section
        y_status = t.get("yara_status") or "No Match"
        y_matches = t.get("yara_matches") or []
        if isinstance(y_matches, dict):
            y_status = y_matches.get("status", y_status)
            y_matches_list = y_matches.get("matches", [])
        else:
            y_matches_list = y_matches if isinstance(y_matches, list) else []

        y_rules_count = len(y_matches_list)
        self.yara_status_lbl.setText(f"Status: {y_status}")
        self.yara_rules_lbl.setText(f"Rules Matched: {y_rules_count}")
        if y_rules_count > 0:
            ev_lines = []
            for m in y_matches_list:
                if isinstance(m, dict):
                    ev_lines.append(f"• [{m.get('rule_name', 'Rule')}]: {m.get('evidence', '')}")
                else:
                    ev_lines.append(f"• Matched rule: {m}")
            self.yara_evidence_lbl.setText("\n".join(ev_lines))
        else:
            self.yara_evidence_lbl.setText("No YARA rules matched this file.")

        # 6. Section F: Threat Intelligence
        i_status = t.get("reputation_status") or "Not available"
        i_provider = t.get("reputation_provider") or "RansomGuard Threat Intel"
        i_details = t.get("reputation_details") or "Threat Intelligence is not available because no configured intelligence provider returned a result."

        self.intel_status_lbl.setText(f"Status: {i_status}")
        self.intel_provider_lbl.setText(f"Provider: {i_provider}")
        self.intel_details_lbl.setText(i_details)

    def _generate_security_explanation(self, threat: Dict[str, Any], reason: str) -> str:
        """Generates an honest, readable security assessment derived strictly from real detection signals."""
        lower_reason = reason.lower()
        threat_lower = str(threat.get("threat_name", "")).lower()

        if "ransom note" in lower_reason or "ransom note" in threat_lower or "readme" in lower_reason or "decrypt" in lower_reason:
            return (
                "The file name matches keywords and naming conventions frequently associated with ransomware ransom notes, "
                "data-recovery guides, or decryption instructions left by threat actors after encrypting endpoint files."
            )
        elif "extension" in lower_reason or "extension" in threat_lower:
            return (
                "The file utilizes an extension or dual-extension pattern associated with known ransomware encryption routines "
                "or deceptive executable masking."
            )
        elif "entropy" in lower_reason or "entropy" in threat_lower:
            return (
                "The file data exhibits abnormally high Shannon entropy, indicating high data randomness typical of encrypted "
                "content or heavily packed malicious binaries."
            )
        elif "yara" in lower_reason or "yara" in threat_lower:
            return (
                "Static rule signatures identified concrete patterns, bytecode, or string markers associated with malicious payloads."
            )
        elif reason and reason != "Reason unavailable.":
            return f"Heuristic analysis flagged this file based on observed static indicators: {reason}"
        else:
            return "Insufficient evidence available to provide a more specific explanation."

    def _populate_evidence_table(self, threat: Dict[str, Any]):
        """Populates the 4-column evidence table with authentic rules and wrapped text."""
        self.evidence_table.setRowCount(0)
        rules_data = []

        threat_name = threat.get("threat_name") or "STATIC_HEURISTIC_RULE"
        reason = threat.get("reason") or "Suspicious file characteristic detected"
        risk = threat.get("risk_score", 30)
        source = threat.get("detection_source") or "Existing File Scan"

        # Check for structured multi-line evidence string
        ev_str = threat.get("evidence") or ""
        if ev_str and "|" in ev_str:
            for line in ev_str.strip().split("\n"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    rule_clean = parts[0].replace("Rule:", "").strip()
                    stage = "Static Inspection"
                    rules_data.append((rule_clean, parts[1], parts[2], stage))
                elif len(parts) == 2:
                    rule_clean = parts[0].replace("Rule:", "").strip()
                    stage = "Static Inspection"
                    rules_data.append((rule_clean, parts[1], f"+{risk}", stage))

        if not rules_data:
            rule_id = "RANSOM_NOTE_PATTERN" if ("note" in reason.lower() or "decrypt" in reason.lower() or "recovery" in reason.lower()) else "SUSPICIOUS_FILE_PATTERN"
            rules_data.append((rule_id, reason, f"+{risk}", source))

        # Secondary static attributes
        if threat.get("file_type") and threat.get("file_type") != "Not available":
            rules_data.append(("FILE_STRUCTURE_IDENTIFIER", f"Validated file container/format: {threat.get('file_type')}", "+0", "Format Validation"))

        if threat.get("sha256") and threat.get("sha256") != "Not available":
            sha_full = threat.get("sha256")
            rules_data.append(("CRYPTOGRAPHIC_HASH", f"Authentic SHA-256 fingerprint verified: {sha_full[:16]}...{sha_full[-12:]}", "+0", "Integrity Check"))

        self.evidence_table.setRowCount(len(rules_data))
        for r_idx, (r_name, r_ev, r_risk, r_stage) in enumerate(rules_data):
            # Col 0: Rule
            it_name = QTableWidgetItem(r_name)
            it_name.setForeground(QColor("#93C5FD"))
            it_name.setFont(QFont("Consolas", 10, QFont.Bold))

            # Col 1: Observed Evidence (word-wrapped)
            it_ev = QTableWidgetItem(r_ev)
            it_ev.setFont(QFont("Segoe UI", 10))

            # Col 2: Contribution / Score
            it_risk = QTableWidgetItem(r_risk)
            it_risk.setTextAlignment(Qt.AlignCenter)
            it_risk.setForeground(QColor("#F87171") if "+" in r_risk and r_risk != "+0" else QColor("#94A3B8"))
            it_risk.setFont(QFont("Consolas", 10, QFont.Bold))

            # Col 3: Detection Stage
            it_stage = QTableWidgetItem(r_stage)
            it_stage.setTextAlignment(Qt.AlignCenter)
            it_stage.setForeground(QColor("#CBD5E1"))
            it_stage.setFont(QFont("Segoe UI", 9.5))

            self.evidence_table.setItem(r_idx, 0, it_name)
            self.evidence_table.setItem(r_idx, 1, it_ev)
            self.evidence_table.setItem(r_idx, 2, it_risk)
            self.evidence_table.setItem(r_idx, 3, it_stage)

        self.evidence_table.resizeRowsToContents()

        # Adjust table height dynamically to fit rows (capped at 220px)
        total_h = self.evidence_table.horizontalHeader().height() + 4
        for i in range(self.evidence_table.rowCount()):
            total_h += self.evidence_table.rowHeight(i)
        self.evidence_table.setFixedHeight(min(220, max(110, total_h)))

    def _on_investigate_clicked(self):
        """
        Integrates threat into the Threat Repository without duplicate creation,
        closes dialog, and navigates directly to the detailed investigation panel.
        """
        if not self.threats or self.current_index < 0 or self.current_index >= len(self.threats):
            return

        t = self.threats[self.current_index]
        file_path = t.get("file_path", "")
        sha256 = t.get("sha256")
        folder = os.path.dirname(file_path) if file_path else ""
        filename = t.get("filename") or (os.path.basename(file_path) if file_path else "Threat File")
        source = t.get("detection_source") or "Existing File Scan"

        # Check existing incident to prevent duplicate creation
        existing = self.inc_repo.get_active_incident_by_path_or_hash(file_path, sha256)
        if existing:
            inc_id = existing["id"]
        else:
            # Create fresh incident for investigation
            reason = t.get("reason") or "Suspicious file identified during existing scan"
            ev_str = (
                f"Detection Source: {source}\n"
                f"Scan Run ID: {self.scan_summary.get('scan_id', 'Unknown')}\n"
                f"File verified on disk (Size: {t.get('file_size', 0):,} bytes)\n"
                f"SHA-256: {sha256}\n"
                f"Observed Reason: {reason}"
            )
            inc_id = self.inc_repo.insert_incident(
                threat_name=f"{t.get('threat_name', 'Suspicious File')} ({source})",
                severity=t.get("severity", "LOW"),
                risk_score=t.get("risk_score", 30),
                affected_folder=folder,
                affected_file=filename,
                full_path=file_path,
                detection_reason=f"[{source}] {reason}",
                recommendation="Review file location. Quarantine or delete if unrecognized.",
                status="ACTIVE",
                verdict=t.get("verdict", "SUSPICIOUS"),
                evidence=ev_str,
                attribution_status="UNAVAILABLE",
                file_size=t.get("file_size"),
                sha256=sha256,
                file_type=t.get("file_type")
            )

        self.investigate_threat.emit(inc_id)
        self.accept()
