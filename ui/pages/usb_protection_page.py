import os
import time
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame,
    QProgressBar, QTableView, QHeaderView, QAbstractItemView, QGridLayout,
    QTabWidget, QDialog, QTextEdit, QScrollArea, QApplication
)
from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QColor

from core.database.database import DatabaseManager
from core.protection.usb_protection_manager import USBProtectionManager, USBDevice
from core.detection.risk_engine import (
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from ui.components.tables import format_file_size


class USBFileDetailsDialog(QDialog):
    """
    SOC/EDR Modal Dialog displaying complete evidence, hash, static indicators,
    and risk telemetry for an analyzed USB storage file.
    """

    def __init__(self, record: Dict[str, Any], parent=None):
        super(USBFileDetailsDialog, self).__init__(parent)
        self.record = record or {}
        self.setWindowTitle("USB File Security Telemetry & Evidence")
        self.setMinimumSize(620, 520)
        self.setStyleSheet("""
            QDialog {
                background-color: #070B16;
                color: #F4F7FF;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                color: #F4F7FF;
            }
            QFrame#cardFrame {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
            QPushButton {
                background-color: #111A2B;
                color: #F4F7FF;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #355B8A;
            }
        """)

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # 1. Header Row
        hdr_frame = QFrame(self)
        hdr_frame.setObjectName("cardFrame")
        hdr_layout = QHBoxLayout(hdr_frame)
        hdr_layout.setContentsMargins(16, 12, 16, 12)

        v = self.record.get("verdict", VERDICT_UNKNOWN)
        filename = self.record.get("filename") or os.path.basename(self.record.get("file_path", "Unknown"))

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(2)
        title_lbl = QLabel(filename, self)
        title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        
        path_lbl = QLabel(self.record.get("file_path", ""), self)
        path_lbl.setStyleSheet("font-size: 11px; color: #8B98A8; font-family: Consolas;")
        path_lbl.setWordWrap(True)

        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(path_lbl)
        hdr_layout.addLayout(title_vbox, stretch=1)

        # Verdict Badge Pill
        verdict_badge = QLabel(f" {v} ", self)
        v_color = "#22C55E" if v == VERDICT_CLEAN else ("#F59E0B" if v == VERDICT_SUSPICIOUS else ("#EF4444" if v == VERDICT_MALICIOUS else "#94A3B8"))
        verdict_badge.setStyleSheet(f"""
            background-color: {v_color}22;
            color: {v_color};
            border: 1px solid {v_color};
            border-radius: 12px;
            padding: 4px 12px;
            font-size: 12px;
            font-weight: bold;
        """)
        hdr_layout.addWidget(verdict_badge)

        layout.addWidget(hdr_frame)

        # 2. Key Attributes Grid
        grid_frame = QFrame(self)
        grid_frame.setObjectName("cardFrame")
        grid = QGridLayout(grid_frame)
        grid.setContentsMargins(16, 14, 16, 14)
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(10)

        raw_size = self.record.get("file_size") or self.record.get("size")
        formatted_sz = format_file_size(raw_size)
        exact_bytes = f"{int(raw_size):,} bytes" if isinstance(raw_size, (int, float)) and raw_size >= 0 else "N/A"

        attributes = [
            ("Detection Source:", self.record.get("detection_source", "USB Initial Scan")),
            ("File Type:", self.record.get("file_type", "Unknown")),
            ("Risk Score:", f"{self.record.get('risk_score', 0)} / 100"),
            ("Severity Level:", str(self.record.get("severity", "LOW")).upper()),
            ("File Size:", f"{formatted_sz} ({exact_bytes})"),
            ("Threat Name:", self.record.get("threat_name", "Clean File")),
        ]

        row = 0
        for label_text, val_text in attributes:
            lbl = QLabel(label_text, self)
            lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: bold;")
            val = QLabel(str(val_text), self)
            val.setStyleSheet("color: #E6EDF3; font-size: 12px; font-weight: 600;")
            
            grid.addWidget(lbl, row // 2, (row % 2) * 2)
            grid.addWidget(val, row // 2, (row % 2) * 2 + 1)
            row += 1

        layout.addWidget(grid_frame)

        # 3. Hash Row
        hash_frame = QFrame(self)
        hash_frame.setObjectName("cardFrame")
        hash_layout = QHBoxLayout(hash_frame)
        hash_layout.setContentsMargins(16, 10, 16, 10)

        sha_lbl_title = QLabel("SHA-256:", self)
        sha_lbl_title.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: bold;")
        self.sha_val_lbl = QLabel(self.record.get("sha256", "Not available"), self)
        self.sha_val_lbl.setStyleSheet("color: #A855F7; font-size: 11px; font-family: Consolas;")
        self.sha_val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)

        copy_btn = QPushButton("📋 Copy Hash", self)
        copy_btn.setFixedHeight(26)
        copy_btn.clicked.connect(self._copy_hash)

        hash_layout.addWidget(sha_lbl_title)
        hash_layout.addWidget(self.sha_val_lbl, stretch=1)
        hash_layout.addWidget(copy_btn)

        layout.addWidget(hash_frame)

        # 4. Evidence & Analysis Reasons
        ev_title = QLabel("DETECTION EVIDENCE & STATIC ANALYSIS REASONING", self)
        ev_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        layout.addWidget(ev_title)

        ev_text = QTextEdit(self)
        ev_text.setReadOnly(True)
        ev_text.setStyleSheet("""
            QTextEdit {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 6px;
                color: #CBD5E1;
                font-family: Consolas, monospace;
                font-size: 11px;
                padding: 10px;
            }
        """)

        evidence_items = self.record.get("evidence_list") or []
        if not evidence_items:
            evidence_items = [self.record.get("reason", "No suspicious indicator detected.")]

        content_lines = [f"• {item}" for item in evidence_items]
        ev_text.setPlainText("\n\n".join(content_lines))
        layout.addWidget(ev_text)

        # 5. Footer Row
        ftr_row = QHBoxLayout()
        ftr_row.addStretch()
        close_btn = QPushButton("Close", self)
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.accept)
        ftr_row.addWidget(close_btn)

        layout.addLayout(ftr_row)

    def _copy_hash(self):
        sha = self.record.get("sha256", "")
        if sha and sha != "Not available":
            QApplication.clipboard().setText(sha)


class USBScanTableModel(QAbstractTableModel):
    """Table model displaying real files analyzed on the connected USB storage."""

    def __init__(self, records=None, parent=None):
        super(USBScanTableModel, self).__init__(parent)
        self.records = records or []
        self.headers = ["File Name", "Detection Source", "Verdict", "Severity", "Risk Score", "Evidence / Reason", "SHA-256", "Size"]

    def rowCount(self, parent=QModelIndex()):
        return len(self.records)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.records):
            return None

        rec = self.records[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return rec.get("filename", "")
            elif col == 1:
                return rec.get("detection_source", "")
            elif col == 2:
                return rec.get("verdict", "")
            elif col == 3:
                return str(rec.get("severity", "LOW")).upper()
            elif col == 4:
                return f"{rec.get('risk_score', 0)}/100"
            elif col == 5:
                return rec.get("reason", "")
            elif col == 6:
                sha = rec.get("sha256", "")
                if sha and sha != "Not available" and len(sha) > 16:
                    return f"{sha[:10]}...{sha[-6:]}"
                return sha
            elif col == 7:
                size_b = rec.get("file_size")
                if size_b is None:
                    size_b = rec.get("size")
                if isinstance(size_b, str):
                    return size_b
                return format_file_size(size_b)

        elif role == Qt.ForegroundRole:
            if col == 2:
                v = rec.get("verdict", "")
                if v == VERDICT_MALICIOUS:
                    return QColor("#EF4444")
                elif v == VERDICT_SUSPICIOUS:
                    return QColor("#F59E0B")
                elif v == VERDICT_CLEAN:
                    return QColor("#22C55E")
                return QColor("#94A3B8")
            elif col == 3:
                sev = str(rec.get("severity", "LOW")).upper()
                if sev == "CRITICAL":
                    return QColor("#EF4444")
                elif sev == "HIGH":
                    return QColor("#F97316")
                elif sev == "MEDIUM":
                    return QColor("#F59E0B")
                return QColor("#3B82F6")
            elif col in (0, 1):
                return QColor("#E6EDF3")
            return QColor("#8B98A8")

        elif role == Qt.TextAlignmentRole:
            if col in (2, 3, 4, 7):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ToolTipRole:
            if col == 0:
                return rec.get("file_path") or rec.get("filename", "")
            elif col in (2, 5):
                return rec.get("reason", "")
            elif col == 6:
                return f"SHA-256: {rec.get('sha256', 'Not available')}"
            elif col == 7:
                size_b = rec.get("file_size") or rec.get("size")
                if size_b is not None and isinstance(size_b, (int, float)) and size_b >= 0:
                    return f"Actual Size: {int(size_b):,} bytes"
                return "Size unavailable"

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def set_records(self, new_records):
        self.beginResetModel()
        self.records = list(new_records)
        self.endResetModel()

    def add_record(self, record):
        self.beginInsertRows(QModelIndex(), len(self.records), len(self.records))
        self.records.append(record)
        self.endInsertRows()

    def get_record_at(self, row: int) -> Optional[Dict[str, Any]]:
        if 0 <= row < len(self.records):
            return self.records[row]
        return None


class USBHistoryTableModel(QAbstractTableModel):
    """Table model displaying past USB scan sessions stored in SQLite database."""

    def __init__(self, sessions=None, parent=None):
        super(USBHistoryTableModel, self).__init__(parent)
        self.sessions = sessions or []
        self.headers = ["Scan ID", "Drive", "Volume Name", "Filesystem", "Status", "Discovered", "Analyzed", "Clean", "Threats", "Duration", "Date / Time"]

    def rowCount(self, parent=QModelIndex()):
        return len(self.sessions)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.sessions):
            return None

        s = self.sessions[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return s.get("scan_id", "")
            elif col == 1:
                return s.get("drive_letter", "")
            elif col == 2:
                return s.get("volume_name", "") or "Removable Disk"
            elif col == 3:
                return s.get("file_system", "") or "Unknown"
            elif col == 4:
                return s.get("status", "COMPLETED")
            elif col == 5:
                return f"{s.get('discovered_count', 0):,}"
            elif col == 6:
                return f"{s.get('analyzed_count', 0):,}"
            elif col == 7:
                return f"{s.get('clean_count', 0):,}"
            elif col == 8:
                return f"{s.get('threat_count', 0):,}"
            elif col == 9:
                dur = s.get("duration_sec", 0.0)
                return f"{dur:.1f}s"
            elif col == 10:
                return s.get("start_time", "")

        elif role == Qt.ForegroundRole:
            if col == 4:
                st = s.get("status", "")
                if st == "COMPLETED":
                    return QColor("#22C55E")
                elif st in ("INTERRUPTED", "CANCELLED"):
                    return QColor("#F59E0B")
                elif st == "SCANNING":
                    return QColor("#A855F7")
                return QColor("#EF4444")
            elif col == 8:
                t = s.get("threat_count", 0)
                return QColor("#EF4444") if t > 0 else QColor("#22C55E")
            elif col in (0, 1):
                return QColor("#E6EDF3")
            return QColor("#8B98A8")

        elif role == Qt.TextAlignmentRole:
            if col in (1, 3, 4, 5, 6, 7, 8, 9, 10):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None

    def set_sessions(self, sessions):
        self.beginResetModel()
        self.sessions = list(sessions or [])
        self.endResetModel()

    def get_session_at(self, row: int) -> Optional[Dict[str, Any]]:
        if 0 <= row < len(self.sessions):
            return self.sessions[row]
        return None


class USBProtectionPage(QWidget):
    """
    Production-grade USB Protection Page.
    Displays genuine Windows removable device metadata, real initial scan progress,
    evidence-based verdicts, continuous real-time detection telemetry, and historical sessions.
    """

    def __init__(self, db_manager=None, parent=None):
        super(USBProtectionPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.usb_manager = USBProtectionManager.get_instance(self.db)

        self._build_ui()
        self._connect_signals()
        self._refresh_device_view()
        self._refresh_history_table()

    def _build_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(14)

        # -------------------------------------------------------------
        # 1. Device Hardware Overview Card
        # -------------------------------------------------------------
        self.device_card = QFrame(self)
        self.device_card.setObjectName("usbDeviceCard")
        self.device_card.setStyleSheet("""
            QFrame#usbDeviceCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
                padding: 16px 20px;
            }
        """)
        dev_layout = QVBoxLayout(self.device_card)
        dev_layout.setSpacing(12)

        # Top row: Identity & Status
        top_row = QHBoxLayout()

        # Left: Device identity
        id_vbox = QVBoxLayout()
        id_vbox.setSpacing(3)
        self.title_lbl = QLabel("💾 USB STORAGE PROTECTION", self)
        self.title_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #38A8FF; letter-spacing: 0.5px;")

        self.device_name_lbl = QLabel("No Device Connected", self)
        self.device_name_lbl.setStyleSheet("font-size: 17px; font-weight: bold; color: #E6EDF3;")

        self.device_meta_lbl = QLabel("Connect a USB storage device to begin protection.", self)
        self.device_meta_lbl.setStyleSheet("font-size: 12px; color: #8B98A8;")

        id_vbox.addWidget(self.title_lbl)
        id_vbox.addWidget(self.device_name_lbl)
        id_vbox.addWidget(self.device_meta_lbl)
        top_row.addLayout(id_vbox)
        top_row.addStretch()

        # Right: Protection Status & Initial Scan Status
        status_vbox = QVBoxLayout()
        status_vbox.setSpacing(4)
        status_vbox.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        status_indicator_row = QHBoxLayout()
        status_indicator_row.setSpacing(6)
        status_indicator_row.addStretch()
        self.status_dot = QLabel("○", self)
        self.status_dot.setStyleSheet("color: #8B98A8; font-size: 13px;")
        self.status_text = QLabel("No Device", self)
        self.status_text.setStyleSheet("color: #8B98A8; font-size: 14px; font-weight: bold;")
        status_indicator_row.addWidget(self.status_dot)
        status_indicator_row.addWidget(self.status_text)
        status_vbox.addLayout(status_indicator_row)

        self.initial_scan_lbl = QLabel("Initial scan: Not started", self)
        self.initial_scan_lbl.setStyleSheet("font-size: 12px; color: #8B98A8;")
        self.initial_scan_lbl.setAlignment(Qt.AlignRight)
        status_vbox.addWidget(self.initial_scan_lbl)

        self.last_scan_lbl = QLabel("Last scan: Not scanned yet", self)
        self.last_scan_lbl.setStyleSheet("font-size: 11px; color: #64748B; font-family: Consolas;")
        self.last_scan_lbl.setAlignment(Qt.AlignRight)
        status_vbox.addWidget(self.last_scan_lbl)

        top_row.addLayout(status_vbox)
        dev_layout.addLayout(top_row)

        # Capacity bar
        self.capacity_container = QWidget(self)
        cap_layout = QVBoxLayout(self.capacity_container)
        cap_layout.setContentsMargins(0, 4, 0, 0)
        cap_layout.setSpacing(4)

        cap_hdr = QHBoxLayout()
        self.capacity_label = QLabel("Storage Usage: Not available", self)
        self.capacity_label.setStyleSheet("color: #8B98A8; font-size: 11px;")
        cap_hdr.addWidget(self.capacity_label)
        cap_hdr.addStretch()
        self.capacity_percent_lbl = QLabel("", self)
        self.capacity_percent_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: bold;")
        cap_hdr.addWidget(self.capacity_percent_lbl)
        cap_layout.addLayout(cap_hdr)

        self.capacity_bar = QProgressBar(self)
        self.capacity_bar.setFixedHeight(6)
        self.capacity_bar.setTextVisible(False)
        self.capacity_bar.setStyleSheet("""
            QProgressBar {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #168BFF;
                border-radius: 2px;
            }
        """)
        self.capacity_bar.setValue(0)
        cap_layout.addWidget(self.capacity_bar)
        dev_layout.addWidget(self.capacity_container)
        self.capacity_container.setVisible(False)

        self.main_layout.addWidget(self.device_card)

        # -------------------------------------------------------------
        # 2. Real Metrics Counters Grid (3 summary cards)
        # -------------------------------------------------------------
        self.metrics_grid = QGridLayout()
        self.metrics_grid.setSpacing(12)

        self.metric_cards = {}
        metrics_def = [
            ("discovered", "FILES DISCOVERED", "Not scanned yet", "Total files enumerated", 0, 0),
            ("analyzed", "FILES ANALYZED", "Not scanned yet", "Unified analyzer throughput", 0, 1),
            ("clean", "CLEAN FILES", "Not scanned yet", "Verified clean", 0, 2),
        ]

        for key, title, init_val, subtext, r, c in metrics_def:
            card = QFrame(self)
            card.setObjectName(f"usbMetric_{key}")
            card.setStyleSheet(f"""
                QFrame#usbMetric_{key} {{
                    background-color: #0D1422;
                    border: 1px solid #1A2940;
                    border-radius: 8px;
                    padding: 12px 14px;
                }}
            """)
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(4, 4, 4, 4)
            c_layout.setSpacing(4)

            t_lbl = QLabel(title, card)
            t_lbl.setStyleSheet("color: #A9B8D4; font-size: 11px; font-weight: bold;")
            v_lbl = QLabel(init_val, card)
            v_lbl.setStyleSheet("color: #E2E8F0; font-size: 18px; font-weight: bold;")
            s_lbl = QLabel(subtext, card)
            s_lbl.setStyleSheet("color: #71809A; font-size: 11px;")

            c_layout.addWidget(t_lbl)
            c_layout.addWidget(v_lbl)
            c_layout.addWidget(s_lbl)
            self.metric_cards[key] = v_lbl
            self.metrics_grid.addWidget(card, r, c)

        self.main_layout.addLayout(self.metrics_grid)

        # -------------------------------------------------------------
        # 3. Scanning Controls & Live Progress Card
        # -------------------------------------------------------------
        self.scan_ctrl_card = QFrame(self)
        self.scan_ctrl_card.setObjectName("usbScanCtrlCard")
        self.scan_ctrl_card.setStyleSheet("""
            QFrame#usbScanCtrlCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
                padding: 12px 16px;
            }
        """)
        ctrl_layout = QVBoxLayout(self.scan_ctrl_card)
        ctrl_layout.setSpacing(10)

        # Action Buttons Row
        btn_row = QHBoxLayout()
        self.rescan_btn = QPushButton("🔍 Rescan USB Device", self)
        self.rescan_btn.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #F4F7FF;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 7px 16px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                border-color: #168BFF;
                color: #FFFFFF;
            }
            QPushButton:disabled {
                background-color: #0D1422;
                color: #64748B;
                border-color: #1A2940;
            }
        """)
        self.rescan_btn.setCursor(Qt.PointingHandCursor)
        self.rescan_btn.setEnabled(False)
        self.rescan_btn.clicked.connect(self._on_rescan_clicked)
        btn_row.addWidget(self.rescan_btn)

        self.cancel_btn = QPushButton("⏹️ Cancel Scan", self)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 77, 103, 0.15);
                color: #FF4D67;
                border: 1px solid rgba(255, 77, 103, 0.3);
                border-radius: 6px;
                padding: 7px 16px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #FF4D67;
                color: #FFFFFF;
            }
        """)
        self.cancel_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        btn_row.addWidget(self.cancel_btn)

        btn_row.addStretch()

        self.status_note = QLabel("Automatic initial scan evaluates pre-existing contents upon connection.", self)
        self.status_note.setStyleSheet("color: #71809A; font-size: 11px;")
        btn_row.addWidget(self.status_note)

        ctrl_layout.addLayout(btn_row)

        # Progress bar container (active during scanning)
        self.progress_container = QWidget(self)
        p_vbox = QVBoxLayout(self.progress_container)
        p_vbox.setContentsMargins(0, 0, 0, 0)
        p_vbox.setSpacing(4)

        self.scan_progress_bar = QProgressBar(self)
        self.scan_progress_bar.setFixedHeight(14)
        self.scan_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 4px;
                text-align: center;
                color: #FFFFFF;
                font-size: 10px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #00E59A;
                border-radius: 3px;
            }
        """)
        self.scan_progress_bar.setValue(0)
        p_vbox.addWidget(self.scan_progress_bar)

        self.current_scan_file_lbl = QLabel("", self)
        self.current_scan_file_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-family: Consolas;")
        self.current_scan_file_lbl.setWordWrap(True)
        p_vbox.addWidget(self.current_scan_file_lbl)

        ctrl_layout.addWidget(self.progress_container)
        self.progress_container.setVisible(False)

        self.main_layout.addWidget(self.scan_ctrl_card)

        # -------------------------------------------------------------
        # 4. Tabbed Container (File Audit & Previous History)
        # -------------------------------------------------------------
        self.tabs = QTabWidget(self)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #111A2B;
                color: #94A3B8;
                border: 1px solid #1A2940;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #17233A;
                color: #38A8FF;
                border: 1px solid #355B8A;
                border-bottom: 2px solid #168BFF;
            }
            QTabBar::tab:hover {
                color: #F8FAFC;
                background-color: #17233A;
            }
        """)

        # Tab 1: File Audit Log
        self.audit_tab = QWidget()
        audit_layout = QVBoxLayout(self.audit_tab)
        audit_layout.setContentsMargins(12, 12, 12, 12)
        audit_layout.setSpacing(8)

        tbl_hdr = QHBoxLayout()
        self.table_title = QLabel("CURRENT USB SCAN FILE AUDIT & EVIDENCE", self.audit_tab)
        self.table_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #A9B8D4;")
        tbl_hdr.addWidget(self.table_title)
        tbl_hdr.addStretch()

        self.view_details_btn = QPushButton("👁️ View File Details", self.audit_tab)
        self.view_details_btn.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #38A8FF;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #70BFFF;
                border-color: #355B8A;
            }
        """)
        self.view_details_btn.clicked.connect(self._open_selected_file_details)
        tbl_hdr.addWidget(self.view_details_btn)

        self.table_count_lbl = QLabel("0 files inspected", self.audit_tab)
        self.table_count_lbl.setStyleSheet("color: #71809A; font-size: 11px;")
        tbl_hdr.addWidget(self.table_count_lbl)
        audit_layout.addLayout(tbl_hdr)

        self.table_model = USBScanTableModel()
        self.model = self.table_model
        self.results_model = self.table_model
        self.table_view = QTableView(self.audit_tab)
        self.table_view.setModel(self.table_model)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setShowGrid(False)
        self.table_view.setStyleSheet("""
            QTableView {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                gridline-color: transparent;
                selection-background-color: #17233A;
                selection-color: #F8FAFC;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #111A2B;
                color: #94A3B8;
                border: none;
                border-bottom: 1px solid #1A2940;
                padding: 6px 10px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        self.table_view.doubleClicked.connect(self._on_table_double_clicked)

        self.table_view.setColumnWidth(0, 180)  # File Name
        self.table_view.setColumnWidth(1, 160)  # Detection Source
        self.table_view.setColumnWidth(2, 100)  # Verdict
        self.table_view.setColumnWidth(3, 80)   # Severity
        self.table_view.setColumnWidth(4, 80)   # Risk Score
        self.table_view.setColumnWidth(5, 260)  # Reason
        self.table_view.setColumnWidth(6, 140)  # SHA-256
        self.table_view.setColumnWidth(7, 80)   # Size

        audit_layout.addWidget(self.table_view)
        self.tabs.addTab(self.audit_tab, "🔍 Current File Audit")

        # Tab 2: Previous Scan History
        self.history_tab = QWidget()
        hist_layout = QVBoxLayout(self.history_tab)
        hist_layout.setContentsMargins(12, 12, 12, 12)
        hist_layout.setSpacing(8)

        hist_hdr = QHBoxLayout()
        hist_title = QLabel("HISTORICAL USB SECURITY SCAN SESSIONS", self.history_tab)
        hist_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8;")
        hist_hdr.addWidget(hist_title)
        hist_hdr.addStretch()

        self.load_hist_session_btn = QPushButton("📂 Load Session File Audit", self.history_tab)
        self.load_hist_session_btn.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #38A8FF;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #70BFFF;
                border-color: #355B8A;
            }
        """)
        self.load_hist_session_btn.clicked.connect(self._on_load_history_session_clicked)
        hist_hdr.addWidget(self.load_hist_session_btn)

        refresh_hist_btn = QPushButton("🔄 Refresh History", self.history_tab)
        refresh_hist_btn.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #94A3B8;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #F8FAFC;
                border-color: #355B8A;
            }
        """)
        refresh_hist_btn.clicked.connect(self._refresh_history_table)
        hist_hdr.addWidget(refresh_hist_btn)
        hist_layout.addLayout(hist_hdr)

        self.history_model = USBHistoryTableModel()
        self.history_view = QTableView(self.history_tab)
        self.history_view.setModel(self.history_model)
        self.history_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_view.horizontalHeader().setStretchLastSection(True)
        self.history_view.verticalHeader().setVisible(False)
        self.history_view.setShowGrid(False)
        self.history_view.setStyleSheet("""
            QTableView {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                gridline-color: transparent;
                selection-background-color: #17233A;
                selection-color: #F8FAFC;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #111A2B;
                color: #94A3B8;
                border: none;
                border-bottom: 1px solid #1A2940;
                padding: 6px 10px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        self.history_view.doubleClicked.connect(self._on_history_double_clicked)

        self.history_view.setColumnWidth(0, 110)  # Scan ID
        self.history_view.setColumnWidth(1, 60)   # Drive
        self.history_view.setColumnWidth(2, 130)  # Volume
        self.history_view.setColumnWidth(3, 80)   # FS
        self.history_view.setColumnWidth(4, 100)  # Status
        self.history_view.setColumnWidth(5, 90)   # Discovered
        self.history_view.setColumnWidth(6, 80)   # Analyzed
        self.history_view.setColumnWidth(7, 70)   # Clean
        self.history_view.setColumnWidth(8, 70)   # Threats
        self.history_view.setColumnWidth(9, 70)   # Duration
        self.history_view.setColumnWidth(10, 140) # Date

        hist_layout.addWidget(self.history_view)
        self.tabs.addTab(self.history_tab, "📜 Previous Scan History")

        self.main_layout.addWidget(self.tabs)

    def _connect_signals(self):
        self.usb_manager.device_connected.connect(self._on_device_connected)
        self.usb_manager.device_removed.connect(self._on_device_removed)
        self.usb_manager.scan_started.connect(self._on_scan_started)
        self.usb_manager.scan_progress.connect(self._on_scan_progress)
        self.usb_manager.scan_finished.connect(self._on_scan_finished)
        self.usb_manager.scan_interrupted.connect(self._on_scan_interrupted)
        self.usb_manager.threat_detected.connect(self._on_threat_detected)

    def _refresh_device_view(self):
        """Refreshes the page state based on currently connected devices."""
        if not self.usb_manager.connected_devices:
            # Empty state
            self.device_name_lbl.setText("No removable USB storage device detected.")
            self.device_meta_lbl.setText("Connect a USB storage device to begin protection.")
            self.status_dot.setText("○")
            self.status_dot.setStyleSheet("color: #8B98A8; font-size: 13px;")
            self.status_text.setText("No Device")
            self.status_text.setStyleSheet("color: #8B98A8; font-size: 14px; font-weight: bold;")
            self.initial_scan_lbl.setText("Initial scan: Not started")
            self.last_scan_lbl.setText("Last scan: Not scanned yet")
            self.capacity_container.setVisible(False)
            self.rescan_btn.setEnabled(False)
            self.cancel_btn.setVisible(False)
            self.progress_container.setVisible(False)

            self.metric_cards["discovered"].setText("Not scanned yet")
            self.metric_cards["analyzed"].setText("Not scanned yet")
            self.metric_cards["clean"].setText("Not scanned yet")
            self.table_model.set_records([])
            self.table_count_lbl.setText("0 files inspected")
            return

        # Use first active removable device
        drive_letter = list(self.usb_manager.connected_devices.keys())[0]
        device = self.usb_manager.connected_devices[drive_letter]

        self.device_name_lbl.setText(f"{device.volume_name} ({device.drive_letter})")
        self.device_meta_lbl.setText(
            f"Filesystem: {device.file_system} · Capacity: {device.total_gb} GB "
            f"· Connected: {device.connected_time}"
        )

        self.capacity_container.setVisible(True)
        self.capacity_label.setText(f"Total: {device.total_gb} GB | Free: {device.free_gb} GB")
        self.capacity_percent_lbl.setText(f"{device.used_percent}% used")
        self.capacity_bar.setValue(int(device.used_percent))

        # Enable rescan only when a device is connected and not actively scanning
        is_scanning = (device.status == "Scanning") or (
            self.usb_manager.active_worker is not None and self.usb_manager.active_worker.isRunning()
        )
        self.rescan_btn.setEnabled(not is_scanning)

        # Protection status
        if device.status == "Protected":
            self.status_dot.setText("●")
            self.status_dot.setStyleSheet("color: #22C55E; font-size: 13px;")
            self.status_text.setText("Protected")
            self.status_text.setStyleSheet("color: #22C55E; font-size: 14px; font-weight: bold;")
        elif device.status == "Scanning":
            self.status_dot.setText("⚡")
            self.status_dot.setStyleSheet("color: #A855F7; font-size: 13px;")
            self.status_text.setText("Scanning")
            self.status_text.setStyleSheet("color: #A855F7; font-size: 14px; font-weight: bold;")
        elif device.status == "Interrupted":
            self.status_dot.setText("○")
            self.status_dot.setStyleSheet("color: #F59E0B; font-size: 13px;")
            self.status_text.setText("Interrupted")
            self.status_text.setStyleSheet("color: #F59E0B; font-size: 14px; font-weight: bold;")
        else:
            self.status_dot.setText("●")
            self.status_dot.setStyleSheet("color: #A855F7; font-size: 13px;")
            self.status_text.setText("Connected")
            self.status_text.setStyleSheet("color: #A855F7; font-size: 14px; font-weight: bold;")

    def _refresh_history_table(self):
        """Loads historical scan sessions from database."""
        sessions = self.usb_manager.get_scan_history(limit=50)
        self.history_model.set_sessions(sessions)

    def _on_device_connected(self, device: USBDevice):
        self._refresh_device_view()

    def _on_device_removed(self, drive_letter: str):
        self._refresh_device_view()

    def _on_scan_started(self, drive_letter: str):
        self.rescan_btn.setEnabled(False)
        self.cancel_btn.setVisible(True)
        self.progress_container.setVisible(True)
        self.scan_progress_bar.setValue(0)
        self.current_scan_file_lbl.setText("Discovering files and initializing multi-worker analyzer pool...")
        self.initial_scan_lbl.setText("Initial scan: Running...")
        self._refresh_device_view()

    def _on_scan_progress(self, current_file: str, analyzed: int, discovered: int):
        self.current_scan_file_lbl.setText(f"Analyzing: {current_file}")
        if discovered > 0:
            pct = int((analyzed / discovered) * 100)
            self.scan_progress_bar.setValue(pct)

        # Update real-time counter metrics
        self.metric_cards["discovered"].setText(f"{discovered:,}")
        self.metric_cards["analyzed"].setText(f"{analyzed:,}")
        if self.usb_manager.active_worker:
            w = self.usb_manager.active_worker
            self.metric_cards["clean"].setText(f"{w.clean_count:,}")

        self.table_count_lbl.setText(f"{analyzed:,} files inspected")

    def _on_scan_finished(self, summary: dict):
        self.rescan_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.progress_container.setVisible(False)

        disc = summary.get("files_discovered", 0)
        analyzed = summary.get("files_analyzed", 0)
        clean = summary.get("clean_count", 0)

        self.metric_cards["discovered"].setText(f"{disc:,}")
        self.metric_cards["analyzed"].setText(f"{analyzed:,}")
        self.metric_cards["clean"].setText(f"{clean:,}")

        self.initial_scan_lbl.setText("Initial scan: Completed")
        self.last_scan_lbl.setText(f"Last scan: {self.usb_manager.last_scan_time or time.strftime('%H:%M:%S')}")
        self.table_model.set_records(summary.get("records", []))
        self.table_count_lbl.setText(f"{analyzed:,} files inspected")

        self._refresh_device_view()
        self._refresh_history_table()

    def _on_scan_interrupted(self, reason: str):
        self.rescan_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.progress_container.setVisible(False)
        self.initial_scan_lbl.setText("Initial scan: Interrupted")
        self.device_meta_lbl.setText(f"{reason}")
        self._refresh_device_view()
        self._refresh_history_table()

    def _on_threat_detected(self, record: dict):
        self.table_model.add_record(record)
        rec_count = len(self.table_model.records)
        self.table_count_lbl.setText(f"{rec_count:,} files inspected")

    def _on_rescan_clicked(self):
        if self.usb_manager.connected_devices:
            drive_letter = list(self.usb_manager.connected_devices.keys())[0]
            # Invalidate cache for manual user rescan
            for k in list(self.usb_manager.scan_cache.keys()):
                if k.upper().startswith(drive_letter.upper()):
                    self.usb_manager.scan_cache.pop(k, None)
            self.usb_manager.start_usb_scan(drive_letter)

    def _on_cancel_clicked(self):
        self.usb_manager.cancel_current_scan()

    def _on_table_double_clicked(self, index: QModelIndex):
        if not index.isValid():
            return
        rec = self.table_model.get_record_at(index.row())
        if rec:
            self._open_file_details_dialog(rec)

    def _open_selected_file_details(self):
        selection = self.table_view.selectionModel().selectedRows()
        if selection:
            rec = self.table_model.get_record_at(selection[0].row())
            if rec:
                self._open_file_details_dialog(rec)

    def _open_file_details_dialog(self, record: Dict[str, Any]):
        dialog = USBFileDetailsDialog(record, self)
        dialog.exec()

    def _on_history_double_clicked(self, index: QModelIndex):
        if not index.isValid():
            return
        sess = self.history_model.get_session_at(index.row())
        if sess:
            self._load_session_results(sess.get("scan_id", ""))

    def _on_load_history_session_clicked(self):
        selection = self.history_view.selectionModel().selectedRows()
        if selection:
            sess = self.history_model.get_session_at(selection[0].row())
            if sess:
                self._load_session_results(sess.get("scan_id", ""))

    def _load_session_results(self, scan_id: str):
        if not scan_id:
            return
        records = self.usb_manager.get_session_details(scan_id)
        if records:
            self.table_model.set_records(records)
            self.table_count_lbl.setText(f"{len(records):,} files loaded from Session {scan_id}")
            self.tabs.setCurrentIndex(0) # Switch to File Audit tab
