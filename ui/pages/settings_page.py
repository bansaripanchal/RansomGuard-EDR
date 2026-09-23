import os
import sys
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame, 
    QCheckBox, QGridLayout, QProgressBar, QComboBox, QScrollArea
)
from PySide6.QtCore import Qt, Signal, QTimer
from core.monitoring.monitor_manager import MonitorManager
from core.monitoring.drive_manager import DriveManager
from core.database.settings_repository import SettingsRepository
from core.database.database import DatabaseManager
from core.scanning.existing_scan_manager import ExistingScanManager, FREQUENCY_MAP

logger = logging.getLogger("RansomGuard.SettingsPage")


class DriveCard(QFrame):
    """
    Interactive card representing a detected physical or logical storage volume.
    Displays authentic filesystem telemetry (label, capacity, free space, drive type)
    and allows user toggling into the EDR protected scope.
    """
    toggled = Signal(str, bool)

    def __init__(self, drive_info, is_protected=False, parent=None):
        super(DriveCard, self).__init__(parent)
        self.drive_info = drive_info
        self.drive_letter = drive_info["letter"].upper()
        if not self.drive_letter.endswith(":"):
            self.drive_letter += ":"
        self.is_protected = is_protected
        self.setCursor(Qt.PointingHandCursor)
        self.setObjectName("driveCard")
        self._init_ui()
        self._update_appearance()

    def _init_ui(self):
        self.card_layout = QVBoxLayout(self)
        self.card_layout.setContentsMargins(14, 12, 14, 12)
        self.card_layout.setSpacing(6)

        # 1. Top Row: Checkbox, Drive letter, Volume Name, Status Badge
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.checkbox = QCheckBox(self)
        self.checkbox.setChecked(self.is_protected)
        self.checkbox.setCursor(Qt.PointingHandCursor)
        self.checkbox.toggled.connect(self._on_checkbox_toggled)
        top_row.addWidget(self.checkbox)

        self.letter_lbl = QLabel(f"{self.drive_letter}\\", self)
        self.letter_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #FFFFFF;")
        top_row.addWidget(self.letter_lbl)

        vol_name = self.drive_info.get("volume_name")
        if vol_name:
            self.vol_lbl = QLabel(f"({vol_name})", self)
            self.vol_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
            top_row.addWidget(self.vol_lbl)

        top_row.addStretch()

        self.status_badge = QLabel(self)
        top_row.addWidget(self.status_badge)
        self.card_layout.addLayout(top_row)

        # 2. Second Row: Drive Type
        drive_type = self._resolve_drive_type()
        self.type_lbl = QLabel(drive_type, self)
        if "System" in drive_type:
            self.type_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #60A5FA;")
        elif "Removable" in drive_type or "USB" in drive_type:
            self.type_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #22D3EE;")
        else:
            self.type_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #94A3B8;")
        self.card_layout.addWidget(self.type_lbl)

        # 3. Third Row: Capacity & Free Space
        total_gb = self.drive_info.get("total_gb", 0.0)
        free_gb = self.drive_info.get("free_gb", 0.0)
        used_pct = self.drive_info.get("used_percent", 0.0)

        space_text = f"{total_gb} GB total · {free_gb} GB free ({used_pct:.1f}% used)"
        self.space_lbl = QLabel(space_text, self)
        self.space_lbl.setStyleSheet("font-size: 12px; color: #D1D5DB;")
        self.card_layout.addWidget(self.space_lbl)

        # 4. Fourth Row: Mini Usage Bar
        self.prog_bar = QProgressBar(self)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(int(used_pct))
        self.prog_bar.setFixedHeight(5)
        self.card_layout.addWidget(self.prog_bar)

    def _resolve_drive_type(self):
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive += ":"
        if self.drive_letter.startswith(system_drive):
            return "System Drive"
        if self.drive_info.get("is_removable"):
            return "Removable Drive"
        return "Data Drive"

    def _update_appearance(self):
        used_pct = self.drive_info.get("used_percent", 0.0)
        chunk_color = "#168BFF"
        if used_pct > 90:
            chunk_color = "#FF4D67"
        elif used_pct > 80:
            chunk_color = "#FFB84D"

        self.prog_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #111A2B;
                border: none;
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
                border-radius: 2px;
            }}
        """)

        if self.is_protected:
            self.setStyleSheet("""
                QFrame#driveCard {
                    background-color: #17233A;
                    border: 1px solid #355B8A;
                    border-radius: 8px;
                }
                QFrame#driveCard:hover {
                    border: 1px solid #168BFF;
                    background-color: #1E2D4A;
                }
            """)
            self.status_badge.setText("● ACTIVE")
            self.status_badge.setStyleSheet("""
                background-color: rgba(0, 229, 154, 0.15);
                color: #00E59A;
                font-size: 11px;
                font-weight: bold;
                border-radius: 4px;
                padding: 2px 8px;
            """)
        else:
            self.setStyleSheet("""
                QFrame#driveCard {
                    background-color: #0D1422;
                    border: 1px solid #1A2940;
                    border-radius: 8px;
                }
                QFrame#driveCard:hover {
                    border: 1px solid #21334D;
                    background-color: #111A2B;
                }
            """)
            self.status_badge.setText("○ NOT MONITORED")
            self.status_badge.setStyleSheet("""
                background-color: rgba(113, 128, 154, 0.15);
                color: #71809A;
                font-size: 11px;
                font-weight: 500;
                border-radius: 4px;
                padding: 2px 8px;
            """)

    def _on_checkbox_toggled(self, checked):
        self.is_protected = checked
        self._update_appearance()
        self.toggled.emit(self.drive_letter, checked)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.checkbox.setChecked(not self.checkbox.isChecked())
        super(DriveCard, self).mousePressEvent(event)

    def isChecked(self):
        return self.checkbox.isChecked()

    def setChecked(self, checked):
        self.checkbox.setChecked(checked)


class SettingsPage(QWidget):
    protection_toggled = Signal(bool)
    monitored_paths_changed = Signal(list)

    def __init__(self, db_manager=None, parent=None):
        super(SettingsPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.settings_repo = SettingsRepository(self.db)
        self.monitor_manager = MonitorManager(self.db)
        self.scan_manager = ExistingScanManager.get_instance(self.db)

        self.drive_cards = {}
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.timeout.connect(self._hide_save_banner)

        self._build_ui()
        self._load_settings()
        self.refresh_drives()

    def _build_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll_area.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        self.content_widget = QWidget()
        self.content_widget.setObjectName("scrollContent")
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(24, 20, 24, 24)
        self.content_layout.setSpacing(16)

        # -------------------------------------------------------------
        # Page Title & Subtitle
        # -------------------------------------------------------------
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        self.page_title = QLabel("EDR Settings", self)
        self.page_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #F3F4F6;")
        header_layout.addWidget(self.page_title)

        self.page_subtitle = QLabel(
            "Configure protection scope, scheduled scanning and endpoint protection behavior.", self
        )
        self.page_subtitle.setStyleSheet("color: #9CA3AF; font-size: 13px;")
        header_layout.addWidget(self.page_subtitle)

        self.content_layout.addLayout(header_layout)

        # -------------------------------------------------------------
        # 1. Protected Drives Section
        # -------------------------------------------------------------
        self.drives_card = QFrame(self)
        self.drives_card.setObjectName("settingsSectionCard")
        self.drives_card.setStyleSheet("""
            QFrame#settingsSectionCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
        """)
        drives_card_layout = QVBoxLayout(self.drives_card)
        drives_card_layout.setContentsMargins(16, 16, 16, 16)
        drives_card_layout.setSpacing(12)

        drives_head = QLabel("PROTECTED DRIVES", self)
        drives_head.setStyleSheet("font-weight: bold; color: #A9B8D4; font-size: 13px; letter-spacing: 0.5px;")
        drives_card_layout.addWidget(drives_head)

        drives_desc = QLabel("Select which Windows drives RansomGuard should monitor and protect.", self)
        drives_desc.setStyleSheet("color: #71809A; font-size: 12px;")
        drives_card_layout.addWidget(drives_desc)

        # Grid for real drive tiles
        self.drives_grid_widget = QWidget(self)
        self.drives_grid = QGridLayout(self.drives_grid_widget)
        self.drives_grid.setContentsMargins(0, 4, 0, 4)
        self.drives_grid.setSpacing(12)
        drives_card_layout.addWidget(self.drives_grid_widget)

        # Bottom action area inside Protected Drives card
        action_layout = QHBoxLayout()
        action_layout.setContentsMargins(0, 8, 0, 0)
        action_layout.setSpacing(0)
        action_layout.addStretch()

        # Right-aligned column containing the Save Button and directly BELOW it the Status Banner
        save_col = QVBoxLayout()
        save_col.setSpacing(8)
        save_col.setAlignment(Qt.AlignRight)

        self.save_scope_btn = QPushButton("💾 Save Protection Settings", self)
        self.save_scope_btn.setCursor(Qt.PointingHandCursor)
        self.save_scope_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                font-weight: 600;
                font-size: 13px;
                padding: 8px 20px;
                border: 1px solid #168BFF;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2596FF, stop:1 #52B5FF);
                border-color: #38A8FF;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0F75DC, stop:1 #168BFF);
            }
        """)
        self.save_scope_btn.clicked.connect(self._save_drive_scope)
        save_col.addWidget(self.save_scope_btn, alignment=Qt.AlignRight)

        # Status banner directly BELOW the Save button
        self.save_banner = QFrame(self)
        self.save_banner.setObjectName("saveStatusBanner")
        self.save_banner.setVisible(False)
        banner_layout = QVBoxLayout(self.save_banner)
        banner_layout.setContentsMargins(14, 8, 14, 8)
        banner_layout.setSpacing(4)

        self.save_banner_title = QLabel("", self.save_banner)
        self.save_banner_title.setObjectName("saveBannerTitle")
        banner_layout.addWidget(self.save_banner_title)

        self.save_banner_detail = QLabel("", self.save_banner)
        self.save_banner_detail.setObjectName("saveBannerDetail")
        banner_layout.addWidget(self.save_banner_detail)

        # Alias for backward compatibility
        self.save_feedback_lbl = self.save_banner_title

        save_col.addWidget(self.save_banner, alignment=Qt.AlignRight)
        action_layout.addLayout(save_col)
        drives_card_layout.addLayout(action_layout)

        self.content_layout.addWidget(self.drives_card)

        # -------------------------------------------------------------
        # 2. Existing File Scan Schedule Section
        # -------------------------------------------------------------
        self.scan_card = QFrame(self)
        self.scan_card.setObjectName("settingsSectionCard")
        self.scan_card.setStyleSheet("""
            QFrame#settingsSectionCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
        """)
        scan_card_layout = QVBoxLayout(self.scan_card)
        scan_card_layout.setContentsMargins(16, 16, 16, 16)
        scan_card_layout.setSpacing(12)

        scan_head = QLabel("EXISTING FILE SCAN", self)
        scan_head.setStyleSheet("font-weight: bold; color: #A9B8D4; font-size: 13px; letter-spacing: 0.5px;")
        scan_card_layout.addWidget(scan_head)

        scan_desc = QLabel(
            "Automatically scan protected drives for pre-existing or modified files.", self
        )
        scan_desc.setStyleSheet("color: #71809A; font-size: 12px;")
        scan_card_layout.addWidget(scan_desc)

        scan_ctrl_layout = QHBoxLayout()
        scan_ctrl_layout.setSpacing(12)

        freq_lbl = QLabel("Scan Frequency:", self)
        freq_lbl.setStyleSheet("color: #E2E8F0; font-weight: 500; font-size: 13px;")
        scan_ctrl_layout.addWidget(freq_lbl)

        self.freq_combo = QComboBox(self)
        for opt in FREQUENCY_MAP.keys():
            self.freq_combo.addItem(opt)
        self.freq_combo.setStyleSheet("""
            QComboBox {
                background-color: #111A2B;
                color: #F8FAFC;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 13px;
                min-width: 150px;
            }
            QComboBox:hover {
                border-color: #355B8A;
            }
            QComboBox QAbstractItemView {
                background-color: #0D1422;
                color: #F8FAFC;
                selection-background-color: #17233A;
                selection-color: #38A8FF;
                border: 1px solid #1A2940;
            }
        """)
        self.freq_combo.currentTextChanged.connect(self._on_frequency_changed)
        scan_ctrl_layout.addWidget(self.freq_combo)

        self.sched_status_badge = QLabel(self)
        scan_ctrl_layout.addWidget(self.sched_status_badge)

        self.next_scan_lbl = QLabel(self)
        self.next_scan_lbl.setStyleSheet("color: #64748B; font-size: 12px; font-style: italic;")
        scan_ctrl_layout.addWidget(self.next_scan_lbl)
        scan_ctrl_layout.addStretch()

        scan_card_layout.addLayout(scan_ctrl_layout)
        self.content_layout.addWidget(self.scan_card)

        # -------------------------------------------------------------
        # 3. Real-Time Protection Section
        # -------------------------------------------------------------
        self.protect_card = QFrame(self)
        self.protect_card.setObjectName("settingsSectionCard")
        self.protect_card.setStyleSheet("""
            QFrame#settingsSectionCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
        """)
        protect_card_layout = QVBoxLayout(self.protect_card)
        protect_card_layout.setContentsMargins(16, 16, 16, 16)
        protect_card_layout.setSpacing(10)

        prot_head = QLabel("REAL-TIME PROTECTION", self)
        prot_head.setStyleSheet("font-weight: bold; color: #A9B8D4; font-size: 13px; letter-spacing: 0.5px;")
        protect_card_layout.addWidget(prot_head)

        prot_row = QHBoxLayout()
        prot_row.setSpacing(12)

        self.protect_status_badge = QLabel(self)
        prot_row.addWidget(self.protect_status_badge)

        self.shield_toggle_btn = QPushButton("ON", self)
        self.shield_toggle_btn.setCursor(Qt.PointingHandCursor)
        self.shield_toggle_btn.setFixedWidth(64)
        self.shield_toggle_btn.clicked.connect(self._toggle_shield)
        prot_row.addWidget(self.shield_toggle_btn)

        self.shield_desc = QLabel(
            "Behavioral monitoring is enabled for selected protected drives.", self
        )
        self.shield_desc.setStyleSheet("color: #71809A; font-size: 12px;")
        prot_row.addWidget(self.shield_desc)
        prot_row.addStretch()

        protect_card_layout.addLayout(prot_row)
        self.content_layout.addWidget(self.protect_card)

        # -------------------------------------------------------------
        # 4. Active Monitored Locations Section
        # -------------------------------------------------------------
        self.paths_card = QFrame(self)
        self.paths_card.setObjectName("settingsSectionCard")
        self.paths_card.setStyleSheet("""
            QFrame#settingsSectionCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 8px;
            }
        """)
        self.paths_card_layout = QVBoxLayout(self.paths_card)
        self.paths_card_layout.setContentsMargins(16, 16, 16, 16)
        self.paths_card_layout.setSpacing(10)

        paths_head = QLabel("ACTIVE MONITORED LOCATIONS", self)
        paths_head.setStyleSheet("font-weight: bold; color: #94A3B8; font-size: 13px; letter-spacing: 0.5px;")
        self.paths_card_layout.addWidget(paths_head)

        paths_desc = QLabel(
            "Resolved filesystem folder paths currently watched by the EDR shield based on your protected drives.", self
        )
        paths_desc.setStyleSheet("color: #9CA3AF; font-size: 12px;")
        self.paths_card_layout.addWidget(paths_desc)

        self.paths_list_layout = QVBoxLayout()
        self.paths_list_layout.setSpacing(8)
        self.paths_card_layout.addLayout(self.paths_list_layout)

        self.content_layout.addWidget(self.paths_card)

        # Add flexible spacer at bottom
        self.content_layout.addStretch()

        self.scroll_area.setWidget(self.content_widget)
        root_layout.addWidget(self.scroll_area)

        # Connect scan manager schedule updates
        self.scan_manager.schedule_updated.connect(self._on_schedule_updated)

    def _load_settings(self):
        """Loads and syncs UI with persistent SQLite configurations."""
        # 1. Sync real-time protection switch
        shield_enabled_str = self.settings_repo.get_setting("protection_enabled", "True")
        self.shield_active = shield_enabled_str.lower() == "true"
        self._update_shield_ui()

        # 2. Sync frequency combo
        current_freq = self.scan_manager.get_frequency()
        idx = self.freq_combo.findText(current_freq)
        if idx >= 0:
            self.freq_combo.blockSignals(True)
            self.freq_combo.setCurrentIndex(idx)
            self.freq_combo.blockSignals(False)
        self._update_next_scan_display()

        # 3. Populate active monitored locations
        self.refresh_paths_list()

    def _update_shield_ui(self):
        """Reflects current protection status on the toggle button and badge."""
        if self.shield_active:
            self.shield_toggle_btn.setText("ON")
            self.shield_toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #22C55E;
                    color: #FFFFFF;
                    font-weight: bold;
                    font-size: 12px;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 10px;
                }
                QPushButton:hover {
                    background-color: #16A34A;
                }
            """)
            self.protect_status_badge.setText("● ACTIVE")
            self.protect_status_badge.setStyleSheet("""
                background-color: rgba(34, 197, 94, 0.15);
                color: #22C55E;
                font-size: 11px;
                font-weight: bold;
                border-radius: 4px;
                padding: 3px 8px;
            """)
            self.shield_desc.setText("Behavioral monitoring is enabled for selected protected drives.")
        else:
            self.shield_toggle_btn.setText("OFF")
            self.shield_toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #334155;
                    color: #94A3B8;
                    font-weight: bold;
                    font-size: 12px;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 10px;
                }
                QPushButton:hover {
                    background-color: #475569;
                }
            """)
            self.protect_status_badge.setText("○ DISABLED")
            self.protect_status_badge.setStyleSheet("""
                background-color: rgba(148, 163, 184, 0.1);
                color: #94A3B8;
                font-size: 11px;
                font-weight: 500;
                border-radius: 4px;
                padding: 3px 8px;
            """)
            self.shield_desc.setText("Behavioral monitoring is currently paused for protected drives.")

    def _toggle_shield(self):
        """Toggles EDR real-time shield on/off."""
        self.shield_active = not self.shield_active
        self.settings_repo.set_setting("protection_enabled", str(self.shield_active))
        self._update_shield_ui()
        self.protection_toggled.emit(self.shield_active)

        if self.shield_active:
            self.monitor_manager.start_monitoring()
        else:
            self.monitor_manager.stop_monitoring()

    def refresh_paths_list(self):
        """Populates the monitored directory list dynamically."""
        while self.paths_list_layout.count():
            item = self.paths_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        paths = self.settings_repo.get_monitored_paths()
        if not paths:
            empty_lbl = QLabel("No paths currently in the active monitoring scope.", self)
            empty_lbl.setStyleSheet("color: #64748B; font-style: italic; font-size: 12px;")
            self.paths_list_layout.addWidget(empty_lbl)
            return

        for p in paths:
            row_frame = QFrame(self)
            row_frame.setStyleSheet("""
                QFrame {
                    background-color: #111A2B;
                    border: 1px solid #1A2940;
                    border-radius: 6px;
                }
            """)
            r_layout = QHBoxLayout(row_frame)
            r_layout.setContentsMargins(12, 8, 12, 8)
            r_layout.setSpacing(16)

            p_lbl = QLabel(f"📁 {p['path']}", self)
            p_lbl.setStyleSheet("color: #F8FAFC; font-weight: 600; font-size: 13px;")
            r_layout.addWidget(p_lbl)

            rec_lbl = QLabel(f"Recursive: {'Yes' if p.get('recursive', True) else 'No'}", self)
            rec_lbl.setStyleSheet("color: #94A3B8; font-size: 12px;")
            r_layout.addWidget(rec_lbl)

            r_layout.addStretch()

            status_lbl = QLabel("● ACTIVE", self)
            status_lbl.setStyleSheet("""
                background-color: rgba(34, 197, 94, 0.12);
                color: #22C55E;
                font-size: 11px;
                font-weight: bold;
                border-radius: 4px;
                padding: 2px 8px;
            """)
            r_layout.addWidget(status_lbl)

            self.paths_list_layout.addWidget(row_frame)

    def refresh_drives(self):
        """Queries genuine Windows partitions dynamically and populates interactive DriveCards."""
        while self.drives_grid.count():
            item = self.drives_grid.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        # Query genuine system drives
        drives = DriveManager.get_active_drives()
        if not drives:
            drives = DriveManager.get_active_drives_cached()

        if not drives:
            empty_lbl = QLabel("No storage volumes detected on system.", self)
            empty_lbl.setStyleSheet("color: #9CA3AF; font-style: italic;")
            self.drives_grid.addWidget(empty_lbl, 0, 0)
            return

        # Read saved drive selection (default to system drive if unconfigured)
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive += ":"

        saved_drives_str = self.settings_repo.get_setting("protected_drives", system_drive)
        saved_drives = []
        for d in saved_drives_str.split(","):
            d = d.strip().upper()
            if d:
                if not d.endswith(":"):
                    d += ":"
                saved_drives.append(d)

        if not saved_drives:
            saved_drives = [system_drive]

        self.drive_cards.clear()

        # Populate drive cards in a responsive 2-column grid
        col_count = 2
        for idx, d in enumerate(drives):
            letter = d["letter"].upper()
            if not letter.endswith(":"):
                letter += ":"
            is_prot = letter in saved_drives

            card = DriveCard(drive_info=d, is_protected=is_prot, parent=self)
            card.toggled.connect(self._on_drive_selection_changed)
            self.drive_cards[letter] = card

            row = idx // col_count
            col = idx % col_count
            self.drives_grid.addWidget(card, row, col)

        # Synchronize active monitored paths
        self.refresh_paths_list()

    def refresh(self):
        """Public refresh hook called when navigating to Settings page."""
        self.refresh_drives()

    def _on_drive_selection_changed(self, letter: str, checked: bool):
        """Called when user changes drive selection before saving; resets feedback banner."""
        self._hide_save_banner()

    def _show_save_success(self, title: str, detail: str):
        """Displays professional success notification banner directly below the Save button."""
        self._save_timer.stop()
        self.save_banner.setStyleSheet("""
            QFrame#saveStatusBanner {
                background-color: rgba(34, 197, 94, 0.14);
                border: 1px solid #22C55E;
                border-radius: 6px;
            }
        """)
        self.save_banner_title.setStyleSheet("""
            QLabel#saveBannerTitle {
                color: #22C55E;
                font-size: 13px;
                font-weight: bold;
                background: transparent;
                border: none;
            }
        """)
        self.save_banner_title.setText(title)

        self.save_banner_detail.setStyleSheet("""
            QLabel#saveBannerDetail {
                color: #86EFAC;
                font-size: 12px;
                font-weight: 500;
                background: transparent;
                border: none;
            }
        """)
        self.save_banner_detail.setText(detail)
        self.save_banner.setVisible(True)
        self._save_timer.start(5000)

    def _show_save_error(self, title: str, detail: str):
        """Displays professional error notification banner directly below the Save button."""
        self._save_timer.stop()
        self.save_banner.setStyleSheet("""
            QFrame#saveStatusBanner {
                background-color: rgba(239, 68, 68, 0.14);
                border: 1px solid #EF4444;
                border-radius: 6px;
            }
        """)
        self.save_banner_title.setStyleSheet("""
            QLabel#saveBannerTitle {
                color: #EF4444;
                font-size: 13px;
                font-weight: bold;
                background: transparent;
                border: none;
            }
        """)
        self.save_banner_title.setText(title)

        self.save_banner_detail.setStyleSheet("""
            QLabel#saveBannerDetail {
                color: #FCA5A5;
                font-size: 12px;
                font-weight: 500;
                background: transparent;
                border: none;
            }
        """)
        self.save_banner_detail.setText(detail)
        self.save_banner.setVisible(True)
        self._save_timer.start(6000)

    def _hide_save_banner(self):
        """Hides the save feedback banner."""
        self.save_banner.setVisible(False)

    def _save_drive_scope(self):
        """
        Handler connected to [ Save Protection Settings ].
        Sequence:
        1. Read currently selected drive checkboxes.
        2. Validate the selection.
        3. Save using the EXISTING protection-scope persistence logic.
        4. Confirm that the save operation succeeded.
        5. Refresh the Active Monitored Locations section.
        6. Display the visible success banner.
        """
        # 1. Read currently selected drive checkboxes
        selected = []
        for drive_letter, card in self.drive_cards.items():
            if card.isChecked():
                letter = drive_letter.strip().rstrip("\\")
                if not letter.endswith(":"):
                    letter += ":"
                selected.append(letter)

        # 2. Validate the selection
        if not selected:
            logger.warning("No drives selected to protect. Rejecting save operation.")
            # Ensure existing configuration is not modified and restore card states
            saved_drives_str = self.settings_repo.get_setting("protected_drives", "C:")
            saved_drives = [d.strip().upper() for d in saved_drives_str.split(",") if d.strip()]
            for letter, card in self.drive_cards.items():
                card.blockSignals(True)
                card.checkbox.blockSignals(True)
                card.setChecked(letter in saved_drives)
                card.is_protected = letter in saved_drives
                card._update_appearance()
                card.checkbox.blockSignals(False)
                card.blockSignals(False)

            self._show_save_error(
                "✕ Failed to save protection settings.",
                "Please try again."
            )
            return

        try:
            # 3. Save using the EXISTING protection-scope persistence logic
            drives_str = ",".join(selected)
            self.settings_repo.set_setting("protected_drives", drives_str)
            logger.info(f"Saved protected drives scope: {drives_str}")

            # Map and update monitored paths in DB
            self.db.execute_write("DELETE FROM monitored_paths")
            for drive in selected:
                drive_clean = drive.strip().rstrip("\\")
                if not drive_clean.endswith(":"):
                    drive_clean += ":"
                self.settings_repo.add_monitored_path(f"{drive_clean}\\", recursive=True)

            # Log to audit history
            from core.database.history_repository import HistoryRepository
            HistoryRepository(self.db).insert_log(
                event_type="SETTINGS_CHANGED",
                severity="LOW",
                description=f"Global active protection scope changed to: {drives_str}",
                target=drives_str,
                action_taken="MONITORED_PATHS_UPDATED"
            )

            # Invalidate database cache and update active watchdog monitor
            self.db.invalidate_active_drives_cache()
            self.monitor_manager.update_monitoring_paths()

            # 4. Confirm that the save operation succeeded
            persisted_drives = self.settings_repo.get_setting("protected_drives", "")
            if not persisted_drives:
                raise RuntimeError("Persistence verification failed: protected_drives is empty after write")

            # Keep checkboxes selected & update active status badges
            for letter, card in self.drive_cards.items():
                card.is_protected = letter in selected
                card._update_appearance()

            # Notify application components
            updated_paths = self.settings_repo.get_monitored_paths()
            self.monitored_paths_changed.emit(updated_paths)

            # 5. Refresh the Active Monitored Locations section
            self.refresh_paths_list()

            # 6. Display the visible success banner
            formatted_drives = [f"{d.strip().rstrip('\\')}\\" for d in selected]
            drives_display = ", ".join(formatted_drives)
            self._show_save_success(
                "✓ Protection settings saved successfully.",
                f"Protected drives: {drives_display}"
            )

        except Exception as e:
            logger.error(f"Failed to save protection settings: {e}", exc_info=True)
            self._show_save_error(
                "✕ Failed to save protection settings.",
                "Please try again."
            )

    def _on_frequency_changed(self, new_freq: str):
        """Called when user selects a new Existing File Scan frequency."""
        self.scan_manager.set_frequency(new_freq)
        self._update_next_scan_display()

    def _on_schedule_updated(self, freq: str, next_scan: str):
        """Updates next scan label when schedule signals an update."""
        self._update_next_scan_display()

    def _update_next_scan_display(self):
        """Reflects real next scan timing or manual/off state."""
        freq = self.scan_manager.get_frequency()
        next_scan = self.scan_manager.get_next_scan_time()

        if freq in ("Manual only", "Off"):
            self.sched_status_badge.setText("● Automated scan disabled")
            self.sched_status_badge.setStyleSheet("""
                background-color: rgba(148, 163, 184, 0.1);
                color: #94A3B8;
                font-size: 11px;
                font-weight: 500;
                border-radius: 4px;
                padding: 3px 8px;
            """)
            self.next_scan_lbl.setText("")
        else:
            self.sched_status_badge.setText("● Automated scan active")
            self.sched_status_badge.setStyleSheet("""
                background-color: rgba(34, 197, 94, 0.15);
                color: #22C55E;
                font-size: 11px;
                font-weight: bold;
                border-radius: 4px;
                padding: 3px 8px;
            """)
            if next_scan:
                self.next_scan_lbl.setText(f"Next scheduled scan: {next_scan}")
            else:
                self.next_scan_lbl.setText("")
