import os
import sys
import psutil
import socket
import platform
import getpass
import time
import datetime
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton, 
    QComboBox, QGridLayout, QProgressBar, QScrollArea, QSizePolicy
)
from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QFont, QColor

from config import COLOR_RED, COLOR_ORANGE, COLOR_GREEN, COLOR_BLUE
from ui.components.charts import SecurityActivityPulseWidget
from core.database.statistics_repository import StatisticsRepository
from core.database.events_repository import EventsRepository
from core.database.incidents_repository import IncidentsRepository
from core.database.settings_repository import SettingsRepository
from core.database.database import DatabaseManager
from core.scanning.existing_scan_manager import ExistingScanManager

logger = logging.getLogger("RansomGuard.DashboardPage")


def _get_system_manufacturer():
    """Retrieve actual hardware manufacturer via Windows BIOS registry without external dependencies."""
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                val, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                if val and val.strip():
                    return val.strip().title()
        except Exception:
            pass
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                val, _ = winreg.QueryValueEx(key, "BaseBoardManufacturer")
                if val and val.strip():
                    return val.strip().title()
        except Exception:
            pass
    return ""


def _format_drive_scope(drives_str: str) -> str:
    r"""Format drive list into standard EDR format, e.g. 'C:\' or 'C:\ + E:\'."""
    if not drives_str:
        sys_drive = os.environ.get("SystemDrive", "C:").rstrip(":").upper() + ":\\"
        return sys_drive
    parts = [p.strip().rstrip(":\\").upper() + ":\\" for p in str(drives_str).split(",") if p.strip()]
    return " + ".join(parts) if parts else "C:\\"


class ClickableAlertFrame(QFrame):
    """
    High-contrast SOC alert row displaying genuine threat incident telemetry.
    """
    view_details = Signal(dict)
    
    def __init__(self, incident_data, parent=None):
        super(ClickableAlertFrame, self).__init__(parent)
        self.incident_data = incident_data
        self.setObjectName("clickableAlertFrame")
        
        sev = incident_data.get("severity", "HIGH").upper()
        if sev == "CRITICAL":
            border_left_col = "#EF4444"
        elif sev == "HIGH":
            border_left_col = "#F97316"
        elif sev == "MEDIUM":
            border_left_col = "#F59E0B"
        else:
            border_left_col = "#3B82F6"
            
        self.setStyleSheet(f"""
            QFrame#clickableAlertFrame {{
                background-color: #0D1218;
                border: 1px solid #1C2630;
                border-left: 4px solid {border_left_col};
                border-radius: 6px;
                padding: 10px 14px;
            }}
            QFrame#clickableAlertFrame:hover {{
                background-color: #10161D;
                border-color: #3B82F6;
                border-left-color: {border_left_col};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        
        # Row 1: Severity Badge, Threat Name, Risk Score, Status & Timestamp
        hdr = QHBoxLayout()
        hdr.setSpacing(10)
        
        # Severity Badge
        sev_lbl = QLabel(f" {sev} ", self)
        if sev == "CRITICAL":
            sev_lbl.setStyleSheet("background-color: rgba(239, 68, 68, 0.3); color: #EF4444; font-weight: bold; font-size: 12px; border-radius: 3px; border: 1px solid #EF4444;")
        elif sev == "HIGH":
            sev_lbl.setStyleSheet("background-color: rgba(249, 115, 22, 0.2); color: #F97316; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        elif sev == "MEDIUM":
            sev_lbl.setStyleSheet("background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        else:
            sev_lbl.setStyleSheet("background-color: rgba(59, 130, 246, 0.2); color: #3B82F6; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        hdr.addWidget(sev_lbl)
        
        # Threat Activity Name
        threat_name = incident_data.get("threat_name", "Security Threat Activity")
        threat_lbl = QLabel(threat_name, self)
        threat_lbl.setStyleSheet("color: #E6EDF3; font-weight: bold; font-size: 15px; background: transparent; border: none;")
        hdr.addWidget(threat_lbl)
        
        # Risk Score Badge
        risk_score = incident_data.get("risk_score", 0)
        risk_lbl = QLabel(f" Risk: {risk_score}/100 ", self)
        risk_lbl.setStyleSheet("background-color: rgba(245, 158, 11, 0.15); color: #F59E0B; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        hdr.addWidget(risk_lbl)
        
        # Status Badge
        status_str = incident_data.get("status", "ACTIVE")
        status_lbl = QLabel(f" {status_str} ", self)
        if status_str == "RESOLVED":
            status_lbl.setStyleSheet("background-color: rgba(34, 197, 94, 0.15); color: #22C55E; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        else:
            status_lbl.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #EF4444; font-weight: bold; font-size: 12px; border-radius: 3px; border: none;")
        hdr.addWidget(status_lbl)
        
        hdr.addStretch()
        
        # Time
        raw_time = incident_data.get("detection_time", "")
        time_lbl = QLabel(raw_time, self)
        time_lbl.setStyleSheet("color: #8B98A8; font-size: 13px; font-family: Consolas; background: transparent; border: none;")
        hdr.addWidget(time_lbl)
        
        layout.addLayout(hdr)
        
        # Row 2: Target Path, Attributed Process, Reason & Investigate Button
        mid_row = QHBoxLayout()
        mid_row.setSpacing(12)
        
        # Target Path
        path = incident_data.get("full_path") or incident_data.get("affected_folder", "")
        short_path = path
        if len(short_path) > 55:
            short_path = short_path[:25] + "..." + short_path[-25:]
        path_lbl = QLabel(f"Target: {short_path}", self)
        path_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas; background: transparent; border: none;")
        path_lbl.setToolTip(str(path))
        path_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        mid_row.addWidget(path_lbl)
        
        # Process Attribution
        proc_name = incident_data.get("process_name")
        proc_pid = incident_data.get("process_pid")
        attr_status = incident_data.get("attribution_status")
        if proc_name and proc_name not in ("Unknown", "Unknown Process"):
            pid_str = f" (PID: {proc_pid})" if proc_pid else ""
            status_str = f" [{attr_status}]" if attr_status else ""
            proc_text = f"Process: {proc_name}{pid_str}{status_str}"
        else:
            proc_text = "Process: Unknown — attribution unavailable"
            
        proc_lbl = QLabel(proc_text, self)
        proc_lbl.setStyleSheet("color: #8B98A8; font-size: 13px; font-family: Consolas; background: transparent; border: none;")
        proc_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        mid_row.addWidget(proc_lbl)
        
        # Detection reason snippet
        reason = incident_data.get("detection_reason", "")
        if reason:
            if len(reason) > 40:
                reason = reason[:37] + "..."
            reason_lbl = QLabel(f"[{reason}]", self)
            reason_lbl.setStyleSheet("color: #6B7280; font-size: 12px; font-style: italic; background: transparent; border: none;")
            mid_row.addWidget(reason_lbl)
            
        mid_row.addStretch()
        
        self.btn_details = QPushButton("Investigate Incident →", self)
        self.btn_details.setStyleSheet("""
            QPushButton {
                background-color: #3B82F6;
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
        """)
        self.btn_details.setCursor(Qt.PointingHandCursor)
        self.btn_details.clicked.connect(lambda: self.view_details.emit(self.incident_data))
        mid_row.addWidget(self.btn_details)
        
        layout.addLayout(mid_row)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.view_details.emit(self.incident_data)
        super(ClickableAlertFrame, self).mousePressEvent(event)


class DashboardPage(QWidget):
    navigate_to_page = Signal(int)
    investigate_incident = Signal(int)

    def __init__(self, parent=None):
        super(DashboardPage, self).__init__(parent)
        self.db = DatabaseManager()
        self.stats_repo = StatisticsRepository(self.db)
        self.events_repo = EventsRepository(self.db)
        self.settings_repo = SettingsRepository(self.db)
        self.inc_repo = IncidentsRepository(self.db)
        self.is_analyzing = False
        self._pending_list_refresh = False
        self._last_list_refresh_time = 0.0
        self._total_files_analyzing_styled = False
        self.sys_labels = {}
        
        # Main layout holds the Scroll Area
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Scroll Area Setup
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.scroll_content = QWidget()
        self.scroll_content.setObjectName("scrollContent")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(20, 16, 20, 20)
        self.scroll_layout.setSpacing(12)

        # Retain dash_container alias pointing to scroll_content for backward compatibility
        self.dash_container = self.scroll_content

        self.scroll_area.setWidget(self.scroll_content)
        self.main_layout.addWidget(self.scroll_area)

        # -------------------------------------------------------------
        # 1. COMPAT STUBS — Hidden widgets for legacy callers that reference these attrs
        # (The large endpoint/status header panel has been removed per user requirement)
        # -------------------------------------------------------------
        self.scope_badge = QLabel(self)
        self.scope_badge.hide()
        self.live_status_badge = QLabel(self)
        self.live_status_badge.hide()
        self.host_meta_lbl = QLabel(self)
        self.host_meta_lbl.hide()
        # status/cap stubs — updated by refresh_data() via hasattr guards
        self.status_dot_lbl = QLabel(self)
        self.status_dot_lbl.hide()
        self.status_text_lbl = QLabel(self)
        self.status_text_lbl.hide()
        self.status_subtext_lbl = QLabel(self)
        self.status_subtext_lbl.hide()
        self.sync_time_lbl = QLabel(self)
        self.sync_time_lbl.hide()
        self.cap_file_mon = QLabel(self)
        self.cap_file_mon.hide()
        self.cap_behavior_det = QLabel(self)
        self.cap_behavior_det.hide()
        self.cap_process_mon = QLabel(self)
        self.cap_process_mon.hide()

        # -------------------------------------------------------------
        # 1B. PROFESSIONAL DASHBOARD HEADER (brand + endpoint context)
        # -------------------------------------------------------------
        self._build_dashboard_header()

        # -------------------------------------------------------------
        # 1C. COMPATIBILITY STUBS FOR REMOVED 4 KPI CARDS
        # (KPI cards permanently removed from layout per specification;
        # stubs preserved in memory so external callers don't throw AttributeError)
        # -------------------------------------------------------------
        self.cards = {
            "total_files": QLabel("0", self),
            "files_monitored": QLabel("0", self),
            "incidents_active": QLabel("0", self),
            "incidents_blocked": QLabel("0", self),
        }
        for stub in self.cards.values():
            stub.hide()

        # -------------------------------------------------------------
        # 2. SECTION 2: Security Activity Pulse + Endpoint Host & EDR Agent Status
        # (Side-by-side row with 50% / 50% balanced distribution)
        # -------------------------------------------------------------
        self.pulse_health_row = QHBoxLayout()
        self.pulse_health_row.setSpacing(12)

        # --- 2A. Security Activity Pulse (left, stretch 1) ---
        self.pulse_card = QFrame(self)
        self.pulse_card.setObjectName("socPulseCard")
        self.pulse_card.setStyleSheet("""
            QFrame#socPulseCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 12px 16px;
            }
        """)
        self.pulse_layout = QVBoxLayout(self.pulse_card)
        self.pulse_layout.setContentsMargins(10, 10, 10, 10)
        self.pulse_layout.setSpacing(8)
        
        p_hdr = QHBoxLayout()
        p_title = QLabel("⚡ SECURITY ACTIVITY PULSE", self.pulse_card)
        p_title.setStyleSheet("font-size: 15px; color: #8B98A8; font-weight: bold; letter-spacing: 0.3px; background: transparent; border: none;")
        p_hdr.addWidget(p_title)
        p_hdr.addStretch()
        self.pulse_layout.addLayout(p_hdr)
        
        self.pulse_widget = SecurityActivityPulseWidget(self.pulse_card)
        self.pulse_layout.addWidget(self.pulse_widget)
        self.pulse_health_row.addWidget(self.pulse_card, 1)

        # --- 2B. Endpoint Host & EDR Agent Status (right, stretch 1) ---
        self._build_endpoint_status_card()
        self.pulse_health_row.addWidget(self.endpoint_status_card, 1)

        self.scroll_layout.addLayout(self.pulse_health_row)

        # -------------------------------------------------------------
        # 3C. EXISTING FILE SCAN (ENDPOINT DISCOVERY)
        # -------------------------------------------------------------
        self.scan_card = QFrame(self)
        self.scan_card.setObjectName("existingScanCard")
        self.scan_card.setStyleSheet("""
            QFrame#existingScanCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 14px 18px;
            }
        """)
        self.scan_card_layout = QVBoxLayout(self.scan_card)
        self.scan_card_layout.setContentsMargins(14, 14, 14, 14)
        self.scan_card_layout.setSpacing(10)

        # Row 1: Header (Title on left, Status Badge on right)
        scan_hdr = QHBoxLayout()
        scan_hdr.setSpacing(10)

        scan_title = QLabel("EXISTING FILE SCAN", self.scan_card)
        scan_title.setStyleSheet("font-size: 16px; color: #E6EDF3; font-weight: bold; letter-spacing: 0.5px; background: transparent; border: none;")
        scan_hdr.addWidget(scan_title)

        scan_hdr.addStretch()

        self.scan_status_badge = QLabel("● IDLE", self.scan_card)
        self.scan_status_badge.setStyleSheet("background-color: rgba(34, 197, 94, 0.1); color: #22C55E; font-size: 13px; font-weight: bold; border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 4px; padding: 3px 12px;")
        scan_hdr.addWidget(self.scan_status_badge)

        self.scan_card_layout.addLayout(scan_hdr)

        # Row 2: Metadata row (Last Scan · Next Scan · Mode)
        self.scan_meta_row = QHBoxLayout()
        self.scan_meta_row.setSpacing(8)

        self.scan_last_time_lbl = QLabel("Last Scan: Never", self.scan_card)
        self.scan_last_time_lbl.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.scan_meta_row.addWidget(self.scan_last_time_lbl)

        self.scan_meta_sep1 = QLabel("·", self.scan_card)
        self.scan_meta_sep1.setStyleSheet("color: #334155; font-size: 12px;")
        self.scan_meta_row.addWidget(self.scan_meta_sep1)

        self.scan_next_time_lbl = QLabel("Next Scan: Calculating...", self.scan_card)
        self.scan_next_time_lbl.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.scan_meta_row.addWidget(self.scan_next_time_lbl)

        self.scan_meta_sep2 = QLabel("·", self.scan_meta_row.parentWidget() if hasattr(self.scan_meta_row, 'parentWidget') else self.scan_card)
        self.scan_meta_sep2.setStyleSheet("color: #334155; font-size: 12px;")
        self.scan_meta_row.addWidget(self.scan_meta_sep2)

        self.scan_mode_lbl = QLabel("Mode:", self.scan_card)
        self.scan_mode_lbl.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.scan_meta_row.addWidget(self.scan_mode_lbl)

        self.scan_mode_combo = QComboBox(self.scan_card)
        self.scan_mode_combo.addItems(["Incremental Scan", "Full Scan"])
        self.scan_mode_combo.setStyleSheet("""
            QComboBox {
                background-color: #0D1218;
                color: #93C5FD;
                border: 1px solid #1C2630;
                border-radius: 4px;
                padding: 2px 8px;
                font-size: 13px;
                font-weight: 500;
            }
            QComboBox::drop-down {
                border: none;
                width: 14px;
            }
            QComboBox QAbstractItemView {
                background-color: #10161D;
                color: #E6EDF3;
                border: 1px solid #1C2630;
                selection-background-color: #1D4ED8;
            }
        """)
        self.scan_meta_row.addWidget(self.scan_mode_combo)

        self.scan_meta_row.addStretch()
        self.scan_card_layout.addLayout(self.scan_meta_row)

        # Row 3: Headline / Activity summary + View Threats Action
        self.scan_summary_layout = QHBoxLayout()
        self.scan_summary_layout.setSpacing(12)

        self.scan_headline_lbl = QLabel("Ready for scheduled or on-demand scan", self.scan_card)
        self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #9CA3AF; margin-top: 2px; background: transparent; border: none;")
        self.scan_summary_layout.addWidget(self.scan_headline_lbl)

        self.btn_view_scan_threats = QPushButton("View Detected Threats", self.scan_card)
        self.btn_view_scan_threats.setStyleSheet("""
            QPushButton {
                background-color: rgba(239, 68, 68, 0.15);
                color: #F87171;
                border: 1px solid rgba(239, 68, 68, 0.4);
                border-radius: 4px;
                padding: 3px 12px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(239, 68, 68, 0.25);
                border-color: #EF4444;
                color: #FFFFFF;
            }
        """)
        self.btn_view_scan_threats.setCursor(Qt.PointingHandCursor)
        self.btn_view_scan_threats.setVisible(False)
        self.btn_view_scan_threats.clicked.connect(self._on_view_scan_threats_clicked)
        self.scan_summary_layout.addWidget(self.btn_view_scan_threats)

        self.scan_summary_layout.addStretch()
        self.scan_card_layout.addLayout(self.scan_summary_layout)

        # Row 4: Real Progress Bar (visible only during scanning / paused)
        self.scan_progress_bar = QProgressBar(self.scan_card)
        self.scan_progress_bar.setRange(0, 100)
        self.scan_progress_bar.setValue(0)
        self.scan_progress_bar.setFixedHeight(6)
        self.scan_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1C2630;
                border-radius: 3px;
                text-align: center;
                background-color: #090D12;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
                border-radius: 2px;
            }
        """)
        self.scan_progress_bar.setTextVisible(False)
        self.scan_progress_bar.setVisible(False)
        self.scan_card_layout.addWidget(self.scan_progress_bar)

        # Row 5: Real Progress Details (files analyzed · pct · ETA)
        self.scan_progress_details_lbl = QLabel("", self.scan_card)
        self.scan_progress_details_lbl.setStyleSheet("font-size: 13px; color: #8B98A8; background: transparent; border: none;")
        self.scan_progress_details_lbl.setVisible(False)
        self.scan_card_layout.addWidget(self.scan_progress_details_lbl)

        # Row 6: Controls (Right-aligned)
        ctrl_layout = QHBoxLayout()
        ctrl_layout.setSpacing(10)
        ctrl_layout.addStretch()

        self.btn_scan_pause = QPushButton("Pause", self.scan_card)
        self.btn_scan_pause.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #E2E8F0;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #334155;
            }
        """)
        self.btn_scan_pause.setCursor(Qt.PointingHandCursor)
        self.btn_scan_pause.setVisible(False)
        self.btn_scan_pause.clicked.connect(self._on_scan_pause_clicked)
        ctrl_layout.addWidget(self.btn_scan_pause)

        self.btn_scan_stop = QPushButton("Stop", self.scan_card)
        self.btn_scan_stop.setStyleSheet("""
            QPushButton {
                background-color: rgba(239, 68, 68, 0.12);
                color: #EF4444;
                border: 1px solid rgba(239, 68, 68, 0.35);
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: rgba(239, 68, 68, 0.25);
            }
        """)
        self.btn_scan_stop.setCursor(Qt.PointingHandCursor)
        self.btn_scan_stop.setVisible(False)
        self.btn_scan_stop.clicked.connect(self._on_scan_stop_clicked)
        ctrl_layout.addWidget(self.btn_scan_stop)

        self.btn_scan_now = QPushButton("Scan Now", self.scan_card)
        self.btn_scan_now.setStyleSheet("""
            QPushButton {
                background-color: #2563EB;
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 6px 18px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1D4ED8;
            }
            QPushButton:disabled {
                background-color: #1E293B;
                color: #64748B;
            }
        """)
        self.btn_scan_now.setCursor(Qt.PointingHandCursor)
        self.btn_scan_now.clicked.connect(self._on_scan_now_clicked)
        ctrl_layout.addWidget(self.btn_scan_now)

        # Compatibility references
        self.btn_scan_toggle = self.btn_scan_now
        self.scan_freq_badge = QLabel("", self.scan_card)
        self.scan_freq_badge.setVisible(False)
        self.scan_current_file_lbl = self.scan_headline_lbl
        self.scan_stat_labels = {}

        self.scan_card_layout.addLayout(ctrl_layout)
        self.scroll_layout.addWidget(self.scan_card)

        # -------------------------------------------------------------
        # 4. LARGE PROMINENT SECTION: Active Security Alerts Console
        # -------------------------------------------------------------
        self.alerts_card = QFrame(self)
        self.alerts_card.setObjectName("socAlertsCard")
        self.alerts_card.setStyleSheet("""
            QFrame#socAlertsCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 14px 18px;
            }
        """)
        self.alerts_layout = QVBoxLayout(self.alerts_card)
        self.alerts_layout.setContentsMargins(10, 10, 10, 10)
        self.alerts_layout.setSpacing(10)
        
        self.alerts_hdr = QHBoxLayout()
        self.alerts_title = QLabel("🚨 ACTIVE SECURITY ALERTS & CORRELATED THREATS", self.alerts_card)
        self.alerts_title.setStyleSheet("font-size: 16px; color: #E6EDF3; font-weight: bold; letter-spacing: 0.3px; background: transparent; border: none;")
        self.alerts_hdr.addWidget(self.alerts_title)
        
        self.alerts_count_badge = QLabel("0 INCIDENTS", self.alerts_card)
        self.alerts_count_badge.setStyleSheet("background-color: #0D1218; color: #8B98A8; font-size: 12px; font-weight: bold; border: 1px solid #1C2630; border-radius: 4px; padding: 2px 6px; margin-left: 8px;")
        self.alerts_hdr.addWidget(self.alerts_count_badge)
        
        self.alerts_hdr.addStretch()
        
        self.btn_view_threats = QPushButton("View Threats Repository →", self.alerts_card)
        self.btn_view_threats.setStyleSheet("background-color: transparent; color: #3B82F6; border: none; font-size: 13px; font-weight: bold;")
        self.btn_view_threats.setCursor(Qt.PointingHandCursor)
        self.btn_view_threats.clicked.connect(lambda: self.navigate_to_page.emit(2))
        self.alerts_hdr.addWidget(self.btn_view_threats)
        self.alerts_layout.addLayout(self.alerts_hdr)
        
        self.alerts_container = QWidget(self.alerts_card)
        self.alerts_list_layout = QVBoxLayout(self.alerts_container)
        self.alerts_list_layout.setContentsMargins(0, 0, 0, 0)
        self.alerts_list_layout.setSpacing(8)
        self.alerts_layout.addWidget(self.alerts_container)
        
        self.scroll_layout.addWidget(self.alerts_card)

        # -------------------------------------------------------------
        # 5. RECENT FILESYSTEM ACTIVITY (AUDIT STREAM) (Full Width)
        # -------------------------------------------------------------
        self.activity_stream_card = QFrame(self)
        self.activity_stream_card.setObjectName("socActivityCard")
        self.activity_stream_card.setStyleSheet("""
            QFrame#socActivityCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 14px 18px;
            }
        """)
        self.activity_stream_layout = QVBoxLayout(self.activity_stream_card)
        self.activity_stream_layout.setContentsMargins(10, 10, 10, 10)
        self.activity_stream_layout.setSpacing(8)
        
        act_hdr = QHBoxLayout()
        act_title = QLabel("⏱️ RECENT FILESYSTEM ACTIVITY (AUDIT STREAM)", self.activity_stream_card)
        act_title.setStyleSheet("font-size: 16px; color: #8B98A8; font-weight: bold; background: transparent; border: none;")
        act_hdr.addWidget(act_title)
        act_hdr.addStretch()
        
        self.btn_view_live = QPushButton("Live Stream →", self.activity_stream_card)
        self.btn_view_live.setStyleSheet("background-color: transparent; color: #3B82F6; border: none; font-size: 13px; font-weight: bold;")
        self.btn_view_live.setCursor(Qt.PointingHandCursor)
        self.btn_view_live.clicked.connect(lambda: self.navigate_to_page.emit(1))
        act_hdr.addWidget(self.btn_view_live)
        self.activity_stream_layout.addLayout(act_hdr)
        
        self.activity_stream_container = QWidget(self.activity_stream_card)
        self.activity_stream_list = QVBoxLayout(self.activity_stream_container)
        self.activity_stream_list.setContentsMargins(0, 0, 0, 0)
        self.activity_stream_list.setSpacing(5)
        self.activity_stream_layout.addWidget(self.activity_stream_container)
        self.scroll_layout.addWidget(self.activity_stream_card)

        # -------------------------------------------------------------
        # 6. Existing File Scan Manager wiring & Initial Data Sync
        # -------------------------------------------------------------

        # Existing File Scan Manager wiring
        self.scan_manager = ExistingScanManager.get_instance(self.db)
        self.scan_manager.scan_started.connect(self._on_existing_scan_started)
        self.scan_manager.scan_progress.connect(self._on_existing_scan_progress)
        self.scan_manager.scan_paused.connect(self._on_existing_scan_paused)
        self.scan_manager.scan_resumed.connect(self._on_existing_scan_resumed)
        self.scan_manager.scan_completed.connect(self._on_existing_scan_completed)
        self.scan_manager.scan_cancelled.connect(self._on_existing_scan_cancelled)
        self.scan_manager.scan_finished.connect(self._on_existing_scan_finished)
        self.scan_manager.scan_interrupted.connect(self._on_existing_scan_interrupted)
        self.scan_manager.schedule_updated.connect(self._on_existing_schedule_updated)
        self._refresh_existing_scan_card()

        self.refresh_data()

    # =============================================================
    # System Health Card
    # =============================================================
    def _build_dashboard_header(self):
        """Compact professional RansomGuard EDR header with real endpoint context."""
        self.dash_header_card = QFrame(self)
        self.dash_header_card.setObjectName("dashHeaderCard")
        self.dash_header_card.setStyleSheet("""
            QFrame#dashHeaderCard {
                background-color: #0A0F16;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 0px;
            }
        """)
        h_main_vbox = QVBoxLayout(self.dash_header_card)
        h_main_vbox.setContentsMargins(18, 10, 18, 10)
        h_main_vbox.setSpacing(8)

        # ── ROW 1: Brand identity on Left, Protection state badge on Right
        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        shield_icon = QLabel("🛡", self.dash_header_card)
        shield_icon.setStyleSheet("font-size: 20px; background: transparent; border: none;")
        top_row.addWidget(shield_icon)

        brand_title = QLabel("RansomGuard EDR", self.dash_header_card)
        brand_title.setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.3px; background: transparent; border: none;")
        top_row.addWidget(brand_title)

        sep_bullet = QLabel("·", self.dash_header_card)
        sep_bullet.setStyleSheet("font-size: 16px; color: #334155; font-weight: bold; background: transparent; border: none;")
        top_row.addWidget(sep_bullet)

        ops_lbl = QLabel("Endpoint Security Operations Center", self.dash_header_card)
        ops_lbl.setStyleSheet("font-size: 13px; color: #4B7BAE; font-weight: 500; background: transparent; border: none;")
        top_row.addWidget(ops_lbl)

        top_row.addStretch()

        # Protection badge
        self.dash_protection_badge = QLabel("● PROTECTED", self.dash_header_card)
        self.dash_protection_badge.setStyleSheet("""
            font-size: 12px; font-weight: 700; color: #22C55E;
            background-color: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 4px;
            padding: 3px 10px;
        """)
        self.dash_protection_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(self.dash_protection_badge)

        h_main_vbox.addLayout(top_row)

        # ── DIVIDER
        h_div = QFrame(self.dash_header_card)
        h_div.setFrameShape(QFrame.Shape.HLine)
        h_div.setStyleSheet("background-color: #1C2630; max-height: 1px; border: none;")
        h_main_vbox.addWidget(h_div)

        # ── ROW 2: Horizontal Info Row (Host · OS · User · Drive)
        info_row = QHBoxLayout()
        info_row.setSpacing(14)

        hostname = socket.gethostname() or "Unknown"
        username = getpass.getuser() or "Unknown"
        os_info = f"{platform.system()} {platform.release()}".strip() or "Unknown"

        try:
            drives_row = self.db.execute_read_one("SELECT value FROM settings WHERE key = 'protected_drives'")
            drives_str = drives_row["value"] if drives_row and drives_row.get("value") else ""
        except Exception:
            drives_str = ""
        formatted_drives = _format_drive_scope(drives_str)

        def _make_info_item(lbl_text, val_text, is_mono=False, val_color="#CBD5E1"):
            box = QHBoxLayout()
            box.setSpacing(6)
            lbl = QLabel(lbl_text, self.dash_header_card)
            lbl.setStyleSheet("color: #64748B; font-size: 12px; font-weight: 600; background: transparent; border: none;")
            val = QLabel(val_text, self.dash_header_card)
            mono_font = "font-family: Consolas, monospace;" if is_mono else ""
            val.setStyleSheet(f"color: {val_color}; font-size: 12px; {mono_font} font-weight: 600; background: transparent; border: none;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            box.addWidget(lbl)
            box.addWidget(val)
            return box, val

        def _make_info_sep():
            sep = QLabel("·", self.dash_header_card)
            sep.setStyleSheet("color: #334155; font-size: 13px; font-weight: bold; background: transparent; border: none;")
            return sep

        b_host, self.header_host_val_lbl = _make_info_item("Host:", hostname, is_mono=True)
        info_row.addLayout(b_host)
        info_row.addWidget(_make_info_sep())

        b_os, self.header_os_val_lbl = _make_info_item("OS:", os_info, is_mono=False)
        info_row.addLayout(b_os)
        info_row.addWidget(_make_info_sep())

        b_user, self.header_user_val_lbl = _make_info_item("User:", username, is_mono=True)
        info_row.addLayout(b_user)
        info_row.addWidget(_make_info_sep())

        b_drive, self.header_drive_val_lbl = _make_info_item("Drive:", formatted_drives, is_mono=True, val_color="#93C5FD")
        info_row.addLayout(b_drive)

        info_row.addStretch()
        h_main_vbox.addLayout(info_row)

        self.scroll_layout.addWidget(self.dash_header_card)

    def _update_dashboard_header(self, shield_active: bool, active_threats: int = 0):
        """Updates the professional header protection badge and drive info with real state."""
        if hasattr(self, "dash_protection_badge") and self.dash_protection_badge:
            if shield_active:
                if active_threats > 0:
                    self.dash_protection_badge.setText("● WARNING")
                    self.dash_protection_badge.setStyleSheet("""
                        font-size: 12px; font-weight: 700; color: #F59E0B;
                        background-color: rgba(245, 158, 11, 0.1);
                        border: 1px solid rgba(245, 158, 11, 0.3);
                        border-radius: 4px; padding: 3px 10px;
                    """)
                else:
                    self.dash_protection_badge.setText("● PROTECTED")
                    self.dash_protection_badge.setStyleSheet("""
                        font-size: 12px; font-weight: 700; color: #22C55E;
                        background-color: rgba(34, 197, 94, 0.1);
                        border: 1px solid rgba(34, 197, 94, 0.3);
                        border-radius: 4px; padding: 3px 10px;
                    """)
            else:
                self.dash_protection_badge.setText("● INACTIVE")
                self.dash_protection_badge.setStyleSheet("""
                    font-size: 12px; font-weight: 700; color: #EF4444;
                    background-color: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.3);
                    border-radius: 4px; padding: 3px 10px;
                """)

        try:
            drives_row = self.db.execute_read_one("SELECT value FROM settings WHERE key = 'protected_drives'")
            drives_str = drives_row["value"] if drives_row and drives_row.get("value") else ""
            formatted = _format_drive_scope(drives_str)
            if hasattr(self, "header_drive_val_lbl") and self.header_drive_val_lbl:
                self.header_drive_val_lbl.setText(formatted)
            if hasattr(self, "status_drive_val_lbl") and self.status_drive_val_lbl:
                self.status_drive_val_lbl.setText(formatted)
            if hasattr(self, "pulse_widget") and self.pulse_widget:
                self.pulse_widget.set_drive_scope(drives_str)
        except Exception:
            pass

    def _build_endpoint_status_card(self):
        """Consolidates endpoint host and EDR agent telemetry into one structured card (6 items)."""
        self.endpoint_status_card = QFrame(self)
        self.endpoint_status_card.setObjectName("endpointStatusCard")
        self.endpoint_status_card.setStyleSheet("""
            QFrame#endpointStatusCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 12px 16px;
            }
        """)
        s_layout = QVBoxLayout(self.endpoint_status_card)
        s_layout.setContentsMargins(10, 10, 10, 10)
        s_layout.setSpacing(6)

        # Card Title
        s_title = QLabel("🖥 ENDPOINT HOST & EDR AGENT STATUS", self.endpoint_status_card)
        s_title.setStyleSheet("font-size: 15px; color: #8B98A8; font-weight: bold; letter-spacing: 0.3px; background: transparent; border: none;")
        s_layout.addWidget(s_title)

        # Subtle separator
        t_sep = QFrame(self.endpoint_status_card)
        t_sep.setFrameShape(QFrame.Shape.HLine)
        t_sep.setStyleSheet("background-color: #1C2630; max-height: 1px; border: none; margin-top: 2px; margin-bottom: 2px;")
        s_layout.addWidget(t_sep)

        hostname = socket.gethostname() or "Unknown"
        username = getpass.getuser() or "Unknown"
        os_info = f"{platform.system()} {platform.release()}".strip() or "Unknown"

        try:
            drives_row = self.db.execute_read_one("SELECT value FROM settings WHERE key = 'protected_drives'")
            drives_str = drives_row["value"] if drives_row and drives_row.get("value") else ""
        except Exception:
            drives_str = ""
        formatted_drives = _format_drive_scope(drives_str)

        def _add_divider():
            d = QFrame(self.endpoint_status_card)
            d.setFrameShape(QFrame.Shape.HLine)
            d.setStyleSheet("background-color: #1C2630; max-height: 1px; border: none; margin: 1px 0px;")
            return d

        # 1. Host
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        l1 = QLabel("Host", self.endpoint_status_card)
        l1.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.status_host_val_lbl = QLabel(hostname, self.endpoint_status_card)
        self.status_host_val_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas, monospace; font-weight: 600; background: transparent; border: none;")
        self.status_host_val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        r1.addWidget(l1)
        r1.addStretch()
        r1.addWidget(self.status_host_val_lbl)
        s_layout.addLayout(r1)
        s_layout.addWidget(_add_divider())

        # 2. User
        r2 = QHBoxLayout()
        r2.setSpacing(8)
        l2 = QLabel("User", self.endpoint_status_card)
        l2.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.status_user_val_lbl = QLabel(username, self.endpoint_status_card)
        self.status_user_val_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas, monospace; font-weight: 600; background: transparent; border: none;")
        self.status_user_val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        r2.addWidget(l2)
        r2.addStretch()
        r2.addWidget(self.status_user_val_lbl)
        s_layout.addLayout(r2)
        s_layout.addWidget(_add_divider())

        # 3. OS
        r3 = QHBoxLayout()
        r3.setSpacing(8)
        l3 = QLabel("OS", self.endpoint_status_card)
        l3.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.status_os_val_lbl = QLabel(os_info, self.endpoint_status_card)
        self.status_os_val_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-weight: 600; background: transparent; border: none;")
        r3.addWidget(l3)
        r3.addStretch()
        r3.addWidget(self.status_os_val_lbl)
        s_layout.addLayout(r3)
        s_layout.addWidget(_add_divider())

        # 4. Drive
        r4 = QHBoxLayout()
        r4.setSpacing(8)
        l4 = QLabel("Drive", self.endpoint_status_card)
        l4.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.status_drive_val_lbl = QLabel(formatted_drives, self.endpoint_status_card)
        self.status_drive_val_lbl.setStyleSheet("color: #93C5FD; font-size: 13px; font-family: Consolas, monospace; font-weight: 600; background: transparent; border: none;")
        self.status_drive_val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        r4.addWidget(l4)
        r4.addStretch()
        r4.addWidget(self.status_drive_val_lbl)
        s_layout.addLayout(r4)
        s_layout.addWidget(_add_divider())

        # 5. CPU Utilization
        cpu_box = QVBoxLayout()
        cpu_box.setSpacing(3)
        cpu_hdr = QHBoxLayout()
        l5 = QLabel("CPU Utilization", self.endpoint_status_card)
        l5.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.cpu_pct_lbl = QLabel("0.0%", self.endpoint_status_card)
        self.cpu_pct_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas, monospace; font-weight: bold; background: transparent; border: none;")
        cpu_hdr.addWidget(l5)
        cpu_hdr.addStretch()
        cpu_hdr.addWidget(self.cpu_pct_lbl)
        cpu_box.addLayout(cpu_hdr)

        self.cpu_bar = QProgressBar(self.endpoint_status_card)
        self.cpu_bar.setTextVisible(False)
        self.cpu_bar.setRange(0, 100)
        self.cpu_bar.setValue(0)
        self.cpu_bar.setFixedHeight(6)
        self.cpu_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1C2630;
                border: none;
                border-radius: 3px;
                max-height: 6px;
            }
            QProgressBar::chunk {
                background-color: #22C55E;
                border-radius: 3px;
            }
        """)
        cpu_box.addWidget(self.cpu_bar)
        s_layout.addLayout(cpu_box)
        s_layout.addWidget(_add_divider())

        # 6. RAM Utilization
        ram_box = QVBoxLayout()
        ram_box.setSpacing(3)
        ram_hdr = QHBoxLayout()
        l6 = QLabel("RAM Utilization", self.endpoint_status_card)
        l6.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
        self.ram_pct_lbl = QLabel("0.0%", self.endpoint_status_card)
        self.ram_pct_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas, monospace; font-weight: bold; background: transparent; border: none;")
        ram_hdr.addWidget(l6)
        ram_hdr.addStretch()
        ram_hdr.addWidget(self.ram_pct_lbl)
        ram_box.addLayout(ram_hdr)

        self.ram_bar = QProgressBar(self.endpoint_status_card)
        self.ram_bar.setTextVisible(False)
        self.ram_bar.setRange(0, 100)
        self.ram_bar.setValue(0)
        self.ram_bar.setFixedHeight(6)
        self.ram_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1C2630;
                border: none;
                border-radius: 3px;
                max-height: 6px;
            }
            QProgressBar::chunk {
                background-color: #22C55E;
                border-radius: 3px;
            }
        """)
        ram_box.addWidget(self.ram_bar)
        s_layout.addLayout(ram_box)

        s_layout.addStretch()

        # Non-blocking 2.5s timer for CPU/RAM metrics
        self._sys_metrics_timer = QTimer(self)
        self._sys_metrics_timer.setInterval(2500)
        self._sys_metrics_timer.timeout.connect(self._update_cpu_ram_metrics)
        self._sys_metrics_timer.start()
        self._update_cpu_ram_metrics()

    def _update_cpu_ram_metrics(self):
        """Reads non-blocking CPU and RAM utilization metrics and updates meter bars."""
        try:
            cpu_val = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            ram_val = mem.percent

            if hasattr(self, "cpu_pct_lbl") and self.cpu_pct_lbl:
                self.cpu_pct_lbl.setText(f"{cpu_val:.1f}%")
            if hasattr(self, "cpu_bar") and self.cpu_bar:
                self.cpu_bar.setValue(int(cpu_val))
                cpu_col = "#22C55E" if cpu_val < 70 else ("#F59E0B" if cpu_val < 85 else "#EF4444")
                self.cpu_bar.setStyleSheet(f"""
                    QProgressBar {{
                        background-color: #1C2630;
                        border: none;
                        border-radius: 3px;
                        max-height: 6px;
                    }}
                    QProgressBar::chunk {{
                        background-color: {cpu_col};
                        border-radius: 3px;
                    }}
                """)

            if hasattr(self, "ram_pct_lbl") and self.ram_pct_lbl:
                self.ram_pct_lbl.setText(f"{ram_val:.1f}%")
            if hasattr(self, "ram_bar") and self.ram_bar:
                self.ram_bar.setValue(int(ram_val))
                ram_col = "#22C55E" if ram_val < 70 else ("#F59E0B" if ram_val < 85 else "#EF4444")
                self.ram_bar.setStyleSheet(f"""
                    QProgressBar {{
                        background-color: #1C2630;
                        border: none;
                        border-radius: 3px;
                        max-height: 6px;
                    }}
                    QProgressBar::chunk {{
                        background-color: {ram_col};
                        border-radius: 3px;
                    }}
                """)
        except Exception as e:
            logger.debug(f"Error updating CPU/RAM metrics: {e}")

    def _build_health_card(self):
        """Compatibility alias for _build_endpoint_status_card."""
        self._build_endpoint_status_card()
        self.health_card_widget = self.endpoint_status_card

    def _update_health_card(self, shield_active: bool):
        """Compatibility no-op for legacy callers."""
        pass

    def _update_system_hardware_stats(self):
        """Backward compatibility alias for _update_cpu_ram_metrics."""
        self._update_cpu_ram_metrics()

    def set_analyzing_state(self, drive_letters):
        """Sets Dashboard visual elements for drive counting without blocking event telemetry."""
        self.is_analyzing = True
        self.scope_badge.setText(f"SCOPE: {drive_letters}")
        self.cards["total_files"].setText("Analyzing...")
        self.cards["total_files"].setStyleSheet("font-size: 16px; color: #F59E0B;")
        if hasattr(self, "pulse_widget") and self.pulse_widget:
            self.pulse_widget.set_total_files(0, "calculating")
            self.pulse_widget.set_drive_scope(drive_letters)
        self.refresh_data()


    def update_total_files(self, total_count, status):
        """Callback from background thread giving incremental discover/analyze updates."""
        if status == "calculating":
            self.cards["total_files"].setText(f"Analyzing... ({total_count:,})")
            if not getattr(self, "_total_files_analyzing_styled", False):
                self.cards["total_files"].setStyleSheet("font-size: 15px; color: #F59E0B;")
                self._total_files_analyzing_styled = True
            if hasattr(self, "pulse_widget") and self.pulse_widget:
                self.pulse_widget.set_total_files(total_count, "calculating")
        else:
            self.is_analyzing = False
            self.cards["total_files"].setText(f"{total_count:,}")
            self.cards["total_files"].setStyleSheet("font-size: 24px; color: #E6EDF3; font-weight: bold;")
            self._total_files_analyzing_styled = False
            if hasattr(self, "pulse_widget") and self.pulse_widget:
                self.pulse_widget.set_total_files(total_count, "done")

    def update_monitored_roots_summary(self, paths):
        """Updates the Header scope and host details with active paths."""
        if not paths:
            self.scope_badge.setText("SCOPE: None")
            return
            
        path_strings = [p["path"] for p in paths]
        summary_str = ", ".join(path_strings)
        
        # Display shortened path summary
        short_paths = []
        for p in paths:
            path_str = p["path"]
            if len(path_str) > 20:
                path_str = path_str[:8] + "..." + path_str[-9:]
            short_paths.append(path_str)
        short_summary_str = ", ".join(short_paths)
        
        self.scope_badge.setText(f"SCOPE: {short_summary_str}")
        if hasattr(self, "pulse_widget") and self.pulse_widget:
            self.pulse_widget.set_drive_scope(summary_str)
        self.refresh_data()

    def refresh(self):
        """Public alias for refreshing dashboard data."""
        self._pending_list_refresh = False
        self.refresh_data()

    def refresh_data(self):
        """Queries database for real telemetry statistics and redraws dashboard metrics."""
        self._displayed_incident_ids = None
        self._displayed_stream_event_ids = None
        try:
            # 1. Update Header context
            system_drive = os.environ.get("SystemDrive", "C:").rstrip(":").upper()
            drives_str = self.db.execute_read_one("SELECT value FROM settings WHERE key = 'protected_drives'")
            active_drives = drives_str["value"] if drives_str else system_drive
            self.scope_badge.setText(f"SCOPE: {active_drives}")
            
            shield_active = self.settings_repo.get_setting("protection_enabled", "True").lower() == "true"
            if shield_active:
                if hasattr(self, "status_dot_lbl"):
                    self.status_dot_lbl.setText("●")
                    self.status_dot_lbl.setStyleSheet("color: #22C55E; font-size: 13px;")
                if hasattr(self, "status_text_lbl"):
                    self.status_text_lbl.setText("Protected")
                    self.status_text_lbl.setStyleSheet("color: #22C55E; font-size: 14px; font-weight: 700;")
                if hasattr(self, "status_subtext_lbl"):
                    self.status_subtext_lbl.setText("Real-time protection active")
                if hasattr(self, "cap_file_mon"):
                    self.cap_file_mon.setText("✓ Active")
                    self.cap_file_mon.setStyleSheet("color: #22C55E; font-size: 12px; font-weight: 600;")
                if hasattr(self, "cap_behavior_det"):
                    self.cap_behavior_det.setText("✓ Active")
                    self.cap_behavior_det.setStyleSheet("color: #22C55E; font-size: 12px; font-weight: 600;")
                if hasattr(self, "cap_process_mon"):
                    self.cap_process_mon.setText("✓ Active")
                    self.cap_process_mon.setStyleSheet("color: #22C55E; font-size: 12px; font-weight: 600;")
                self.live_status_badge.setText("● LIVE ACTIVE")
                self.live_status_badge.setStyleSheet("background-color: rgba(34, 197, 94, 0.15); color: #22C55E; font-size: 11px; font-weight: bold; border: 1px solid rgba(34, 197, 94, 0.4); border-radius: 4px; padding: 3px 8px;")
            else:
                if hasattr(self, "status_dot_lbl"):
                    self.status_dot_lbl.setText("○")
                    self.status_dot_lbl.setStyleSheet("color: #EF4444; font-size: 13px;")
                if hasattr(self, "status_text_lbl"):
                    self.status_text_lbl.setText("Unprotected")
                    self.status_text_lbl.setStyleSheet("color: #EF4444; font-size: 14px; font-weight: 700;")
                if hasattr(self, "status_subtext_lbl"):
                    self.status_subtext_lbl.setText("Real-time protection stopped")
                if hasattr(self, "cap_file_mon"):
                    self.cap_file_mon.setText("○ Stopped")
                    self.cap_file_mon.setStyleSheet("color: #EF4444; font-size: 12px; font-weight: 600;")
                if hasattr(self, "cap_behavior_det"):
                    self.cap_behavior_det.setText("○ Stopped")
                    self.cap_behavior_det.setStyleSheet("color: #EF4444; font-size: 12px; font-weight: 600;")
                if hasattr(self, "cap_process_mon"):
                    self.cap_process_mon.setText("○ Stopped")
                    self.cap_process_mon.setStyleSheet("color: #EF4444; font-size: 12px; font-weight: 600;")
                self.live_status_badge.setText("○ INACTIVE")
                self.live_status_badge.setStyleSheet("background-color: rgba(156, 163, 175, 0.15); color: #8B98A8; font-size: 11px; font-weight: bold; border: 1px solid rgba(156, 163, 175, 0.4); border-radius: 4px; padding: 3px 8px;")

            # Update Health Card with real protection state
            self._update_health_card(shield_active)

            # Timestamp (legacy stub)
            self.sync_time_lbl.setText(f"Last checked: {datetime.datetime.now().strftime('%H:%M:%S')}")


            # 2. Query summary statistics from SQLite
            stats = self.stats_repo.get_dashboard_summary()
            
            # File count
            if not getattr(self, "is_analyzing", False):
                count_str = self.settings_repo.get_setting("total_files_count", "0")
                total_files = int(count_str) if count_str else 0
                self.cards["total_files"].setText(f"{total_files:,}")
                self.cards["total_files"].setStyleSheet("font-size: 24px; color: #E6EDF3; font-weight: bold;")
                if hasattr(self, "pulse_widget") and self.pulse_widget:
                    self.pulse_widget.set_total_files(total_files, "done")
            
            # Total events monitored
            self.cards["files_monitored"].setText(f"{stats.get('events_today_total', 0):,}")
            self.cards["files_monitored"].setStyleSheet("font-size: 24px; color: #E6EDF3; font-weight: bold;")
            
            inc_act = int(stats.get("incidents_active", 0) or 0)
            self.cards["incidents_active"].setText(str(inc_act))
            if inc_act > 0:
                self.cards["incidents_active"].setStyleSheet("font-size: 24px; color: #EF4444; font-weight: bold;")
            else:
                self.cards["incidents_active"].setStyleSheet("font-size: 24px; color: #E6EDF3; font-weight: bold;")
            
            self.cards["incidents_blocked"].setText(str(stats.get("incidents_blocked", 0)))
            self.cards["incidents_blocked"].setStyleSheet("font-size: 24px; color: #22C55E; font-weight: bold;")

            # Update Header protection status with real incident telemetry
            if hasattr(self, "_update_dashboard_header"):
                self._update_dashboard_header(shield_active, inc_act)

            # Update CPU & RAM metrics
            if hasattr(self, "_update_cpu_ram_metrics"):
                self._update_cpu_ram_metrics()

            # Update Pulse Widget with real database stats and drive scope
            if hasattr(self, "pulse_widget") and self.pulse_widget:
                self.pulse_widget.set_drive_scope(active_drives)
                self.pulse_widget.set_stats(stats)

            # 3. Refresh Alerts Panel & 4. Activity Stream
            now = time.time()
            self._refresh_recent_alerts()
            self._refresh_recent_activity_stream()
            self._last_list_refresh_time = now
            self._pending_list_refresh = False

            # 5. Refresh Existing File Scan Card
            self._refresh_existing_scan_card()

        except Exception as e:
            logger.error(f"Error refreshing dashboard statistics: {e}", exc_info=True)

    def update_statistics(self, stats):
        """Real-time stats updates pushed by the EDR BatchProcessor."""
        if not stats:
            return
            
        # Total files
        if not getattr(self, "is_analyzing", False):
            count_str = self.settings_repo.get_setting("total_files_count", "0")
            total_files = int(count_str) if count_str else 0
            self.cards["total_files"].setText(f"{total_files:,}")
        
        self.cards["files_monitored"].setText(f"{stats.get('events_today_total', 0):,}")
        
        inc_act = int(stats.get("incidents_active", 0) or 0)
        self.cards["incidents_active"].setText(str(inc_act))
        if inc_act > 0:
            self.cards["incidents_active"].setStyleSheet("font-size: 24px; color: #EF4444; font-weight: bold;")
        else:
            self.cards["incidents_active"].setStyleSheet("font-size: 24px; color: #E6EDF3; font-weight: bold;")
            
        self.cards["incidents_blocked"].setText(str(stats.get("incidents_blocked", 0)))

        # Update Pulse Donut Widget
        self.pulse_widget.set_stats(stats)
            
        self.sync_time_lbl.setText(f"Last checked: {datetime.datetime.now().strftime('%H:%M:%S')}")
        
        now = time.time()
        if not self.isVisible():
            self._pending_list_refresh = True
            return

        if (now - getattr(self, "_last_list_refresh_time", 0.0) >= 2.0) or getattr(self, "_pending_list_refresh", False):
            self._refresh_recent_alerts()
            self._refresh_recent_activity_stream()
            self._last_list_refresh_time = now
            self._pending_list_refresh = False

    def _refresh_recent_alerts(self):
        """Pulls recent incidents filtered by active drives from incidents repository."""
        # Query total count of active incidents in active scope
        total_active_count = self.inc_repo.get_active_incidents_count()
        self.alerts_count_badge.setText(f"{total_active_count} INCIDENT{'S' if total_active_count != 1 else ''}")
        if total_active_count > 0:
            self.alerts_count_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #EF4444; font-size: 12px; font-weight: bold; border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 4px; padding: 2px 6px; margin-left: 8px;")
        else:
            self.alerts_count_badge.setStyleSheet("background-color: #0D1218; color: #8B98A8; font-size: 12px; font-weight: bold; border: 1px solid #1C2630; border-radius: 4px; padding: 2px 6px; margin-left: 8px;")

        # Query up to 6 most recent real ACTIVE incidents inside the active scope
        incidents_rows = self.inc_repo.get_incidents(status_filter="ACTIVE", limit=6)
        incidents = [dict(r) for r in incidents_rows]

        # Check if displayed items are already up to date
        current_inc_ids = [inc.get("id") for inc in incidents]
        if hasattr(self, "_displayed_incident_ids") and self._displayed_incident_ids == current_inc_ids and getattr(self, "_displayed_active_count", None) == total_active_count:
            return

        self._displayed_incident_ids = current_inc_ids
        self._displayed_active_count = total_active_count

        layout = self.alerts_list_layout
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()

        if not incidents:
            empty_frame = QFrame(self.alerts_container)
            empty_frame.setObjectName("emptyAlertFrame")
            empty_frame.setStyleSheet("""
                QFrame#emptyAlertFrame {
                    background-color: #0D1218;
                    border: 1px solid #1C2630;
                    border-radius: 6px;
                    padding: 16px 20px;
                }
            """)
            e_layout = QHBoxLayout(empty_frame)
            e_layout.setContentsMargins(8, 8, 8, 8)
            e_layout.setSpacing(14)
            
            shield_icon = QLabel("🛡️", empty_frame)
            shield_icon.setStyleSheet("font-size: 22px; background: transparent; border: none;")
            e_layout.addWidget(shield_icon)
            
            t_box = QVBoxLayout()
            t_box.setSpacing(3)
            empty_lbl = QLabel("No Active Security Threats", empty_frame)
            empty_lbl.setStyleSheet("color: #22C55E; font-weight: bold; font-size: 14px; background: transparent; border: none;")
            
            empty_sub = QLabel("RansomGuard is currently monitoring the protected endpoint.", empty_frame)
            empty_sub.setStyleSheet("color: #8B98A8; font-size: 13px; background: transparent; border: none;")
            
            t_box.addWidget(empty_lbl)
            t_box.addWidget(empty_sub)
            e_layout.addLayout(t_box)
            e_layout.addStretch()
            layout.addWidget(empty_frame)
            return

        for inc in incidents:
            alert_card = ClickableAlertFrame(inc, self.alerts_container)
            alert_card.view_details.connect(self._on_view_alert_details)
            layout.addWidget(alert_card)

    def _refresh_recent_activity_stream(self):
        """Pulls the latest 6 real filesystem events and renders a timeline stream."""
        events_rows = self.events_repo.get_events(limit=6)
        events = [dict(r) for r in events_rows]

        current_ev_ids = [ev.get("id") for ev in events]
        if hasattr(self, "_displayed_stream_event_ids") and self._displayed_stream_event_ids == current_ev_ids:
            return

        self._displayed_stream_event_ids = current_ev_ids

        layout = self.activity_stream_list
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
                widget.deleteLater()

        if not events:
            empty_lbl = QLabel("No recent filesystem activity recorded.", self.activity_stream_container)
            empty_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; padding: 8px; background: transparent; border: none;")
            layout.addWidget(empty_lbl)
            return

        for idx, ev in enumerate(events):
            row_frame = QFrame(self.activity_stream_container)
            row_id = f"streamRow_{idx}"
            row_frame.setObjectName(row_id)
            row_frame.setStyleSheet(f"""
                QFrame#{row_id} {{
                    background-color: #0D1218;
                    border: 1px solid #1C2630;
                    border-radius: 4px;
                    padding: 4px 8px;
                }}
                QFrame#{row_id}:hover {{
                    background-color: #10161D;
                    border-color: #3B82F6;
                }}
            """)
            r_layout = QHBoxLayout(row_frame)
            r_layout.setContentsMargins(4, 2, 4, 2)
            r_layout.setSpacing(8)

            # Time badge
            ts = ev.get("timestamp", "")
            time_str = ts.split(" ")[-1] if " " in ts else ts
            time_lbl = QLabel(time_str, row_frame)
            time_lbl.setStyleSheet("color: #8B98A8; font-size: 12px; font-family: Consolas; background: transparent; border: none;")
            r_layout.addWidget(time_lbl)

            # Op Pill
            op = ev.get("event_type", "EVENT").upper()
            op_lbl = QLabel(f" {op} ", row_frame)
            if "CREATE" in op:
                op_lbl.setStyleSheet("background-color: rgba(34, 197, 94, 0.15); color: #22C55E; font-weight: bold; font-size: 11px; border-radius: 2px; border: none;")
            elif "MODIF" in op:
                op_lbl.setStyleSheet("background-color: rgba(59, 130, 246, 0.15); color: #3B82F6; font-weight: bold; font-size: 11px; border-radius: 2px; border: none;")
            elif "RENAM" in op:
                op_lbl.setStyleSheet("background-color: rgba(245, 158, 11, 0.15); color: #F59E0B; font-weight: bold; font-size: 11px; border-radius: 2px; border: none;")
            else:
                op_lbl.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #EF4444; font-weight: bold; font-size: 11px; border-radius: 2px; border: none;")
            r_layout.addWidget(op_lbl)

            # Path info
            src_path = ev.get("src_path", "")
            dest_path = ev.get("dest_path", "")
            if op == "RENAME" and dest_path:
                path_display = f"{src_path} → {dest_path}"
            else:
                path_display = src_path

            # Truncate if visually too long but set tooltip with full path
            short_path = path_display
            if len(short_path) > 60:
                short_path = short_path[:28] + "..." + short_path[-28:]
            path_lbl = QLabel(short_path, row_frame)
            path_lbl.setStyleSheet("color: #E6EDF3; font-size: 13px; font-family: Consolas; background: transparent; border: none;")
            path_lbl.setToolTip(path_display)
            r_layout.addWidget(path_lbl)

            r_layout.addStretch()

            # File size
            from ui.components.tables import format_file_size
            f_size = ev.get("file_size")
            size_str = format_file_size(f_size)
            size_lbl = QLabel(size_str, row_frame)
            size_lbl.setStyleSheet("color: #8B98A8; font-size: 12px; font-family: Consolas; background: transparent; border: none;")
            r_layout.addWidget(size_lbl)

            layout.addWidget(row_frame)

    def _on_view_alert_details(self, incident_data):
        """Open Threat Repository and inspect the specific incident."""
        inc_id = incident_data.get("id") if isinstance(incident_data, dict) else None
        if inc_id:
            self.investigate_incident.emit(int(inc_id))
        else:
            self.navigate_to_page.emit(2)

    def showEvent(self, event):
        """Called when Dashboard becomes visible. Refreshes deferred UI lists with latest telemetry."""
        super(DashboardPage, self).showEvent(event)
        now = time.time()
        if getattr(self, "_pending_list_refresh", True) or (now - getattr(self, "_last_list_refresh_time", 0.0) >= 2.0):
            self._refresh_recent_alerts()
            self._refresh_recent_activity_stream()
            self._last_list_refresh_time = now
            self._pending_list_refresh = False

    def _update_system_hardware_stats(self):
        """Deprecated hardware polling stub."""
        pass

    # =============================================================
    # Existing File Scan (Endpoint Discovery) Handlers
    # =============================================================
    def _set_ui_state_idle(self):
        self._current_ui_scan_state = "IDLE"
        self.scan_status_badge.setText("● IDLE")
        self.scan_status_badge.setStyleSheet("background-color: rgba(34, 197, 94, 0.1); color: #22C55E; font-size: 13px; font-weight: bold; border: 1px solid rgba(34, 197, 94, 0.25); border-radius: 4px; padding: 3px 12px;")
        self.scan_last_time_lbl.setVisible(True)
        self.scan_meta_sep1.setVisible(True)
        self.scan_next_time_lbl.setVisible(True)
        self.scan_meta_sep2.setVisible(True)
        self.scan_mode_lbl.setVisible(True)
        self.scan_mode_combo.setVisible(True)
        self.scan_mode_combo.setEnabled(True)
        self.scan_progress_bar.setVisible(False)
        self.scan_progress_details_lbl.setVisible(False)
        if hasattr(self, "btn_view_scan_threats"):
            self.btn_view_scan_threats.setVisible(False)
        self.btn_scan_now.setVisible(True)
        self.btn_scan_now.setEnabled(True)
        self.btn_scan_pause.setVisible(False)
        self.btn_scan_stop.setVisible(False)

    def _set_ui_state_scanning(self, headline="Analyzing existing files..."):
        self._current_ui_scan_state = "SCANNING"
        self.scan_status_badge.setText("● SCANNING")
        self.scan_status_badge.setStyleSheet("background-color: rgba(59, 130, 246, 0.12); color: #3B82F6; font-size: 13px; font-weight: bold; border: 1px solid rgba(59, 130, 246, 0.35); border-radius: 4px; padding: 3px 12px;")
        self.scan_headline_lbl.setText(headline)
        self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #E6EDF3; margin-top: 2px; background: transparent; border: none;")
        self.scan_mode_combo.setEnabled(False)
        self.scan_progress_bar.setVisible(True)
        self.scan_progress_details_lbl.setVisible(True)
        if hasattr(self, "btn_view_scan_threats"):
            self.btn_view_scan_threats.setVisible(False)
        self.btn_scan_now.setVisible(False)
        self.btn_scan_pause.setText("Pause")
        self.btn_scan_pause.setVisible(True)
        self.btn_scan_pause.setEnabled(True)
        self.btn_scan_stop.setVisible(True)
        self.btn_scan_stop.setEnabled(True)

    def _set_ui_state_paused(self):
        self._current_ui_scan_state = "PAUSED"
        self.scan_status_badge.setText("● PAUSED")
        self.scan_status_badge.setStyleSheet("background-color: rgba(245, 158, 11, 0.12); color: #F59E0B; font-size: 13px; font-weight: bold; border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 4px; padding: 3px 12px;")
        self.scan_headline_lbl.setText("Scan paused")
        self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #F59E0B; margin-top: 2px; background: transparent; border: none;")
        self.btn_scan_pause.setText("Resume")
        self.btn_scan_pause.setVisible(True)
        self.btn_scan_stop.setVisible(True)
        if hasattr(self, "btn_view_scan_threats"):
            self.btn_view_scan_threats.setVisible(False)

    def _set_ui_state_completed(self, summary: dict):
        self._current_ui_scan_state = "COMPLETED"
        self.scan_status_badge.setText("● COMPLETED")
        self.scan_status_badge.setStyleSheet("background-color: rgba(34, 197, 94, 0.12); color: #22C55E; font-size: 13px; font-weight: bold; border: 1px solid rgba(34, 197, 94, 0.35); border-radius: 4px; padding: 3px 12px;")
        analyzed = summary.get("files_analyzed", 0) or summary.get("analyzed_count", 0)
        threats = summary.get("threats_found", 0) or summary.get("threat_count", 0)
        if threats == 0:
            self.scan_headline_lbl.setText(f"✓ Scan completed · {analyzed:,} files checked · No threats found")
            self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #22C55E; margin-top: 2px; background: transparent; border: none;")
            if hasattr(self, "btn_view_scan_threats"):
                self.btn_view_scan_threats.setVisible(False)
        else:
            self.scan_headline_lbl.setText(f"⚠️ Scan completed · {analyzed:,} files checked · {threats} threat{'s' if threats > 1 else ''} detected")
            self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #EF4444; margin-top: 2px; background: transparent; border: none;")
            if hasattr(self, "btn_view_scan_threats"):
                self.btn_view_scan_threats.setText(f"View {threats} Detected Threat{'s' if threats > 1 else ''}")
                self.btn_view_scan_threats.setVisible(True)
        self.scan_progress_bar.setVisible(False)
        self.scan_progress_details_lbl.setVisible(False)
        self.scan_mode_combo.setEnabled(True)
        self.btn_scan_now.setVisible(True)
        self.btn_scan_now.setEnabled(True)
        self.btn_scan_pause.setVisible(False)
        self.btn_scan_stop.setVisible(False)

    def _set_ui_state_cancelled(self, summary: dict):
        self._current_ui_scan_state = "STOPPED"
        self.scan_status_badge.setText("● STOPPED")
        self.scan_status_badge.setStyleSheet("background-color: rgba(156, 163, 175, 0.12); color: #9CA3AF; font-size: 13px; font-weight: bold; border: 1px solid rgba(156, 163, 175, 0.35); border-radius: 4px; padding: 3px 12px;")
        analyzed = summary.get("files_analyzed", 0) or summary.get("analyzed_count", 0)
        threats = summary.get("threats_found", 0) or summary.get("threat_count", 0)
        if threats > 0:
            self.scan_headline_lbl.setText(f"⚠️ Scan stopped · {analyzed:,} files checked · {threats} threat{'s' if threats > 1 else ''} detected")
            self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #EF4444; margin-top: 2px; background: transparent; border: none;")
            if hasattr(self, "btn_view_scan_threats"):
                self.btn_view_scan_threats.setText(f"View {threats} Detected Threat{'s' if threats > 1 else ''}")
                self.btn_view_scan_threats.setVisible(True)
        else:
            self.scan_headline_lbl.setText(f"Scan stopped · {analyzed:,} files checked before interruption")
            self.scan_headline_lbl.setStyleSheet("font-size: 13px; color: #9CA3AF; margin-top: 2px; background: transparent; border: none;")
            if hasattr(self, "btn_view_scan_threats"):
                self.btn_view_scan_threats.setVisible(False)
        self.scan_progress_bar.setVisible(False)
        self.scan_progress_details_lbl.setVisible(False)
        self.scan_mode_combo.setEnabled(True)
        self.btn_scan_now.setVisible(True)
        self.btn_scan_now.setEnabled(True)
        self.btn_scan_pause.setVisible(False)
        self.btn_scan_stop.setVisible(False)

    def _on_view_scan_threats_clicked(self):
        """Opens modal dialog showing authentic threats detected by the scan."""
        threats = self.scan_manager.get_last_scan_threats()
        summary = self.scan_manager.get_last_scan_summary() or {}
        from ui.components.scan_threats_dialog import ScanThreatsDialog
        dlg = ScanThreatsDialog(threats=threats, scan_summary=summary, db_manager=self.db, parent=self)
        dlg.investigate_threat.connect(self._on_investigate_threat_from_dialog)
        dlg.exec()

    def _on_investigate_threat_from_dialog(self, incident_id: int):
        """Relays investigate action from ScanThreatsDialog to MainWindow / ThreatsPage."""
        self.investigate_incident.emit(incident_id)

    def _refresh_existing_scan_card(self):
        """Updates Existing File Scan card widgets with real state and timings."""
        try:
            freq = self.scan_manager.get_frequency()
            last_time = self.scan_manager.get_last_scan_time()
            if last_time == "Not scanned yet":
                self.scan_last_time_lbl.setText("Last Scan: Never")
            else:
                self.scan_last_time_lbl.setText(f"Last Scan: {last_time}")

            next_time = self.scan_manager.get_next_scan_time()
            if freq in ("Manual only", "Off"):
                self.scan_next_time_lbl.setText(f"Automated Scan: {freq}")
            else:
                self.scan_next_time_lbl.setText(f"Next Scan: {next_time}")

            if self.scan_manager.is_scanning():
                if self.scan_manager.is_paused():
                    self._set_ui_state_paused()
                else:
                    self._set_ui_state_scanning()
            else:
                summary = self.scan_manager.get_last_scan_summary()
                if summary:
                    self._set_ui_state_completed(summary)
                else:
                    self._set_ui_state_idle()
                    self.scan_headline_lbl.setText("Ready for scheduled or on-demand scan")
                    self.scan_headline_lbl.setStyleSheet("font-size: 12px; color: #9CA3AF; margin-top: 2px; background: transparent; border: none;")
        except Exception as e:
            logger.error(f"Error refreshing existing scan card: {e}", exc_info=True)

    def _on_scan_now_clicked(self):
        """Launches an on-demand Existing File Scan session."""
        selected_mode = "INCREMENTAL"
        if hasattr(self, "scan_mode_combo") and "full" in self.scan_mode_combo.currentText().lower():
            selected_mode = "FULL"
        self.btn_scan_now.setEnabled(False)
        self.scan_manager.start_scan(mode=selected_mode)
        self.btn_scan_now.setEnabled(True)

    def _on_scan_pause_clicked(self):
        """Toggles pause/resume state for the active scan."""
        if self.scan_manager.is_paused():
            self.scan_manager.resume_scan()
        else:
            self.scan_manager.pause_scan()

    def _on_scan_stop_clicked(self):
        """Stops the active scan gracefully."""
        self.btn_scan_stop.setEnabled(False)
        self.scan_manager.stop_scan()
        self.btn_scan_stop.setEnabled(True)

    def _on_scan_button_clicked(self):
        """Compatibility wrapper for legacy callers."""
        self._on_scan_now_clicked()

    def _on_existing_scan_started(self, data):
        if isinstance(data, list):
            drives_str = ", ".join(data)
        elif isinstance(data, dict):
            drives_str = ", ".join(data.get("protected_drives", []))
        else:
            drives_str = ""
        headline = f"Starting discovery across protected scope: {drives_str}" if drives_str else "Starting discovery across protected drives..."
        self._set_ui_state_scanning(headline=headline)
        self.scan_progress_bar.setValue(0)
        self.scan_progress_details_lbl.setText("Discovering existing files...")

    def _on_existing_scan_progress(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], dict):
            stats = args[0]
            analyzed = stats.get("analyzed_count", 0)
            discovered = stats.get("discovered_count", 0)
            pct = int(stats.get("progress_percent", 0.0))
            time_str = stats.get("time_remaining_str", "Calculating...")
            status = stats.get("status", "SCANNING")
            if status == "DISCOVERING":
                if getattr(self, "_current_ui_scan_state", None) != "DISCOVERING":
                    self._set_ui_state_scanning(headline="Discovering & analyzing files across protected scope...")
                    self._current_ui_scan_state = "DISCOVERING"
                if analyzed > 0:
                    self.scan_progress_details_lbl.setText(f"{analyzed:,} analyzed · {discovered:,} discovered so far...")
                    calc_pct = int((analyzed / max(1, discovered)) * 100) if discovered > 0 else 0
                    self.scan_progress_bar.setValue(min(99, max(1, calc_pct)))
                else:
                    self.scan_progress_details_lbl.setText(f"{discovered:,} files discovered so far...")
                    self.scan_progress_bar.setValue(0)
            elif status == "PAUSED":
                if getattr(self, "_current_ui_scan_state", None) != "PAUSED":
                    self._set_ui_state_paused()
                self.scan_progress_details_lbl.setText(f"{analyzed:,} files analyzed · {pct}% · Paused")
            else:
                if getattr(self, "_current_ui_scan_state", None) != "SCANNING":
                    self._set_ui_state_scanning(headline="Analyzing existing files...")
                self.scan_progress_bar.setValue(min(100, max(0, pct)))
                self.scan_progress_details_lbl.setText(f"{analyzed:,} / {discovered:,} files analyzed · {pct}% · {time_str}")
        elif len(args) >= 4:
            file_path, analyzed, discovered, threats = args[:4]
            pct = int((analyzed / max(1, discovered)) * 100) if discovered > 0 else 0
            if getattr(self, "_current_ui_scan_state", None) != "SCANNING":
                self._set_ui_state_scanning()
            self.scan_progress_bar.setValue(min(100, pct))
            self.scan_progress_details_lbl.setText(f"{analyzed:,} files analyzed · {pct}%")

    def _on_existing_scan_paused(self):
        self._set_ui_state_paused()

    def _on_existing_scan_resumed(self):
        self._set_ui_state_scanning()

    def _on_existing_scan_completed(self, summary: dict):
        self._refresh_existing_scan_card()
        self._set_ui_state_completed(summary)
        self.refresh_data()

    def _on_existing_scan_cancelled(self, summary: dict):
        self._refresh_existing_scan_card()
        if isinstance(summary, str):
            summary = {"files_analyzed": 0, "threats_found": 0}
        self._set_ui_state_cancelled(summary)

    def _on_existing_scan_finished(self, summary: dict):
        self._on_existing_scan_completed(summary)

    def _on_existing_scan_interrupted(self, reason: str):
        self._on_existing_scan_cancelled({"files_analyzed": 0, "threats_found": 0})

    def _on_existing_schedule_updated(self, freq: str, next_scan: str):
        if freq in ("Manual only", "Off"):
            self.scan_next_time_lbl.setText(f"Automated Scan: {freq}")
        else:
            self.scan_next_time_lbl.setText(f"Next Scan: {next_scan}")
        if hasattr(self, "scan_freq_badge"):
            self.scan_freq_badge.setText(f"Frequency: {freq}")
