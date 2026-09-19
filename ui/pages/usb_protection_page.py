import os
import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame,
    QProgressBar, QTableView, QHeaderView, QAbstractItemView, QGridLayout,
    QScrollArea
)
from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QColor

from core.database.database import DatabaseManager
from core.protection.usb_protection_manager import USBProtectionManager, USBDevice
from core.detection.risk_engine import (
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)

class USBScanTableModel(QAbstractTableModel):
    """Table model displaying real files analyzed on the connected USB storage."""
    def __init__(self, records=None, parent=None):
        super(USBScanTableModel, self).__init__(parent)
        self.records = records or []
        self.headers = ["File Name", "Detection Source", "Verdict", "Evidence / Reason", "SHA-256", "Size"]

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
                return rec.get("reason", "")
            elif col == 4:
                sha = rec.get("sha256", "")
                if sha and sha != "Not available" and len(sha) > 16:
                    return f"{sha[:10]}...{sha[-6:]}"
                return sha
            elif col == 5:
                size_b = rec.get("file_size")
                if size_b is None:
                    size_b = rec.get("size")
                if isinstance(size_b, str):
                    return size_b
                from ui.components.tables import format_file_size
                return format_file_size(size_b)

        elif role == Qt.ForegroundRole:
            if col == 2:
                v = rec.get("verdict", "")
                if v == VERDICT_MALICIOUS:
                    return QColor("#EF4444") # Red
                elif v == VERDICT_SUSPICIOUS:
                    return QColor("#F59E0B") # Amber
                elif v == VERDICT_CLEAN:
                    return QColor("#22C55E") # Green
                return QColor("#94A3B8")     # Muted
            elif col in (0, 1):
                return QColor("#E6EDF3")
            return QColor("#8B98A8")

        elif role == Qt.TextAlignmentRole:
            if col in (2, 5):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        elif role == Qt.ToolTipRole:
            if col == 0:
                return rec.get("file_path") or rec.get("filename", "")
            elif col == 2:
                return rec.get("reason", "")
            elif col == 4:
                return f"SHA-256: {rec.get('sha256', 'Not available')}"
            elif col == 5:
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


class USBProtectionPage(QWidget):
    """
    Production-grade USB Protection Page.
    Displays genuine Windows removable device metadata, real initial scan progress,
    evidence-based verdicts, and continuous real-time detection telemetry.
    """
    def __init__(self, db_manager=None, parent=None):
        super(USBProtectionPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.usb_manager = USBProtectionManager.get_instance(self.db)

        self._build_ui()
        self._connect_signals()
        self._refresh_device_view()

    def _build_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(16)

        # -------------------------------------------------------------
        # 1. Device Hardware Overview Card
        # -------------------------------------------------------------
        self.device_card = QFrame(self)
        self.device_card.setObjectName("usbDeviceCard")
        self.device_card.setStyleSheet("""
            QFrame#usbDeviceCard {
                background-color: #0D1117;
                border: 1px solid #1C2630;
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
        self.title_lbl = QLabel("USB STORAGE PROTECTION", self)
        self.title_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #3B82F6; letter-spacing: 0.5px;")
        
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
                background-color: #161B22;
                border: 1px solid #1C2630;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
                border-radius: 2px;
            }
        """)
        self.capacity_bar.setValue(0)
        cap_layout.addWidget(self.capacity_bar)
        dev_layout.addWidget(self.capacity_container)
        self.capacity_container.setVisible(False)

        self.main_layout.addWidget(self.device_card)

        # -------------------------------------------------------------
        # 2. Real Metrics Counters Grid (4 summary cards)
        # -------------------------------------------------------------
        self.metrics_grid = QGridLayout()
        self.metrics_grid.setSpacing(12)
        
        self.metric_cards = {}
        metrics_def = [
            ("discovered", "FILES DISCOVERED", "Not scanned yet", "Total files on USB", 0, 0),
            ("analyzed", "FILES ANALYZED", "Not scanned yet", "Unified analyzer throughput", 0, 1),
            ("clean", "CLEAN FILES", "Not scanned yet", "Verified clean", 0, 2),
            ("threats", "THREATS IDENTIFIED", "Not scanned yet", "Suspicious / Malicious", 0, 3)
        ]

        for key, title, init_val, subtext, r, c in metrics_def:
            card = QFrame(self)
            card.setObjectName(f"usbMetric_{key}")
            card.setStyleSheet(f"""
                QFrame#usbMetric_{key} {{
                    background-color: #0D1117;
                    border: 1px solid #1C2630;
                    border-radius: 8px;
                    padding: 12px 14px;
                }}
            """)
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(4, 4, 4, 4)
            c_layout.setSpacing(4)

            t_lbl = QLabel(title, card)
            t_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: bold;")
            v_lbl = QLabel(init_val, card)
            v_lbl.setStyleSheet("color: #E6EDF3; font-size: 18px; font-weight: bold;")
            s_lbl = QLabel(subtext, card)
            s_lbl.setStyleSheet("color: #64748B; font-size: 11px;")

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
                background-color: #0D1117;
                border: 1px solid #1C2630;
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
                background-color: #1E293B;
                color: #E6EDF3;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 7px 16px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563EB;
                border-color: #3B82F6;
                color: #FFFFFF;
            }
            QPushButton:disabled {
                background-color: #111827;
                color: #4B5563;
                border-color: #1F2937;
            }
        """)
        self.rescan_btn.setCursor(Qt.PointingHandCursor)
        self.rescan_btn.setEnabled(False)
        self.rescan_btn.clicked.connect(self._on_rescan_clicked)
        btn_row.addWidget(self.rescan_btn)

        self.cancel_btn = QPushButton("⏹️ Cancel Scan", self)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(239, 68, 68, 0.15);
                color: #EF4444;
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 6px;
                padding: 7px 16px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #EF4444;
                color: #FFFFFF;
            }
        """)
        self.cancel_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        btn_row.addWidget(self.cancel_btn)

        btn_row.addStretch()
        
        self.status_note = QLabel("Automatic initial scan evaluates pre-existing contents upon connection.", self)
        self.status_note.setStyleSheet("color: #64748B; font-size: 11px;")
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
                background-color: #161B22;
                border: 1px solid #1C2630;
                border-radius: 4px;
                text-align: center;
                color: #FFFFFF;
                font-size: 10px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #22C55E;
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
        # 4. Analyzed Contents & Threat Audit Table
        # -------------------------------------------------------------
        self.table_card = QFrame(self)
        self.table_card.setObjectName("usbTableCard")
        self.table_card.setStyleSheet("""
            QFrame#usbTableCard {
                background-color: #0D1117;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 12px 16px;
            }
        """)
        tbl_layout = QVBoxLayout(self.table_card)
        tbl_layout.setSpacing(8)

        tbl_hdr = QHBoxLayout()
        self.table_title = QLabel("USB FILE SECURITY AUDIT & VERDICTS", self)
        self.table_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8;")
        tbl_hdr.addWidget(self.table_title)
        tbl_hdr.addStretch()

        self.table_count_lbl = QLabel("0 files inspected", self)
        self.table_count_lbl.setStyleSheet("color: #64748B; font-size: 11px;")
        tbl_hdr.addWidget(self.table_count_lbl)
        tbl_layout.addLayout(tbl_hdr)

        self.table_model = USBScanTableModel()
        self.model = self.table_model         # Standard table model alias across RansomGuard pages
        self.results_model = self.table_model # Verification and API convenience alias
        self.table_view = QTableView(self)
        self.table_view.setModel(self.table_model)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setShowGrid(False)
        self.table_view.setStyleSheet("""
            QTableView {
                background-color: #090D12;
                border: 1px solid #1C2630;
                border-radius: 6px;
                gridline-color: transparent;
                selection-background-color: #1E293B;
                selection-color: #FFFFFF;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QHeaderView::section {
                background-color: #10161D;
                color: #8B98A8;
                border: none;
                border-bottom: 1px solid #1C2630;
                padding: 6px 10px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
            }
        """)
        
        self.table_view.setColumnWidth(0, 180) # File Name
        self.table_view.setColumnWidth(1, 160) # Detection Source
        self.table_view.setColumnWidth(2, 110) # Verdict
        self.table_view.setColumnWidth(3, 300) # Reason
        self.table_view.setColumnWidth(4, 150) # SHA-256
        self.table_view.setColumnWidth(5, 80)  # Size

        tbl_layout.addWidget(self.table_view)
        self.main_layout.addWidget(self.table_card)

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
            # Production empty state
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
            self.metric_cards["threats"].setText("Not scanned yet")
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
            self.status_dot.setStyleSheet("color: #3B82F6; font-size: 13px;")
            self.status_text.setText("Scanning")
            self.status_text.setStyleSheet("color: #3B82F6; font-size: 14px; font-weight: bold;")
        elif device.status == "Interrupted":
            self.status_dot.setText("○")
            self.status_dot.setStyleSheet("color: #F59E0B; font-size: 13px;")
            self.status_text.setText("Interrupted")
            self.status_text.setStyleSheet("color: #F59E0B; font-size: 14px; font-weight: bold;")
        else:
            self.status_dot.setText("●")
            self.status_dot.setStyleSheet("color: #3B82F6; font-size: 13px;")
            self.status_text.setText("Connected")
            self.status_text.setStyleSheet("color: #3B82F6; font-size: 14px; font-weight: bold;")

    def _on_device_connected(self, device: USBDevice):
        self._refresh_device_view()

    def _on_device_removed(self, drive_letter: str):
        self._refresh_device_view()

    def _on_scan_started(self, drive_letter: str):
        self.rescan_btn.setEnabled(False)
        self.cancel_btn.setVisible(True)
        self.progress_container.setVisible(True)
        self.scan_progress_bar.setValue(0)
        self.current_scan_file_lbl.setText("Discovering files and initializing unified analyzer...")
        self.initial_scan_lbl.setText("Initial scan: Running...")
        self._refresh_device_view()

    def _on_scan_progress(self, current_file: str, analyzed: int, discovered: int):
        self.current_scan_file_lbl.setText(f"Analyzing: {current_file}")
        if discovered > 0:
            pct = int((analyzed / discovered) * 100)
            self.scan_progress_bar.setValue(pct)
        self.metric_cards["discovered"].setText(f"{discovered:,}")
        self.metric_cards["analyzed"].setText(f"{analyzed:,}")
        self.table_count_lbl.setText(f"{analyzed:,} files inspected")

    def _on_scan_finished(self, summary: dict):
        self.rescan_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.progress_container.setVisible(False)

        disc = summary.get("files_discovered", 0)
        analyzed = summary.get("files_analyzed", 0)
        clean = summary.get("clean_count", 0)
        threats = summary.get("threats_found", 0)

        self.metric_cards["discovered"].setText(f"{disc:,}")
        self.metric_cards["analyzed"].setText(f"{analyzed:,}")
        self.metric_cards["clean"].setText(f"{clean:,}")
        self.metric_cards["threats"].setText(f"{threats:,}")
        if threats > 0:
            self.metric_cards["threats"].setStyleSheet("color: #EF4444; font-size: 18px; font-weight: bold;")
        else:
            self.metric_cards["threats"].setStyleSheet("color: #22C55E; font-size: 18px; font-weight: bold;")

        self.initial_scan_lbl.setText("Initial scan: Completed")
        self.last_scan_lbl.setText(f"Last scan: {self.usb_manager.last_scan_time or time.strftime('%H:%M:%S')}")
        self.table_model.set_records(summary.get("records", []))
        self.table_count_lbl.setText(f"{analyzed:,} files inspected")
        self._refresh_device_view()

    def _on_scan_interrupted(self, reason: str):
        self.rescan_btn.setEnabled(True)
        self.cancel_btn.setVisible(False)
        self.progress_container.setVisible(False)
        self.initial_scan_lbl.setText("Initial scan: Interrupted")
        self.device_meta_lbl.setText(f"{reason}")
        self._refresh_device_view()

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
