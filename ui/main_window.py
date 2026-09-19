import os
import sys
import logging
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QStackedWidget, QApplication
)
from PySide6.QtCore import Qt, Signal

from ui.components.sidebar import Sidebar
from ui.components.topbar import Topbar
from ui.pages.dashboard_page import DashboardPage
from ui.pages.live_protection_page import LiveProtectionPage
from ui.pages.threats_page import ThreatsPage
from ui.pages.scan_page import ScanPage
from ui.pages.reports_page import ReportsPage
from ui.pages.history_page import HistoryPage
from ui.pages.settings_page import SettingsPage
from ui.pages.about_page import AboutPage
from ui.pages.usb_protection_page import USBProtectionPage

from core.monitoring.monitor_manager import MonitorManager
from core.database.settings_repository import SettingsRepository
from core.database.database import DatabaseManager
from core.scanning.existing_scan_manager import ExistingScanManager

logger = logging.getLogger("RansomGuard.MainWindow")

# Windows message struct for device change listening
if sys.platform.startswith("win"):
    import ctypes
    from ctypes import wintypes
    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", wintypes.WPARAM),
            ("lParam", wintypes.LPARAM),
            ("time", wintypes.DWORD),
            ("pt", wintypes.POINT),
        ]

class MainWindow(QMainWindow):
    def __init__(self, db_manager=None, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("RansomGuard EDR")
        self.resize(1200, 720)
        self.setMinimumSize(1000, 620)
        self._center_on_screen()

        self.db = db_manager or DatabaseManager()
        self.settings_repo = SettingsRepository(self.db)
        self.monitor_manager = MonitorManager(self.db)

        # Central widget layout
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 1. Left Sidebar
        self.sidebar = Sidebar(self)
        self.main_layout.addWidget(self.sidebar)

        # 2. Right Pane container (Topbar + Stacked Pages)
        self.right_container = QWidget(self)
        self.right_layout = QVBoxLayout(self.right_container)
        self.right_layout.setContentsMargins(0, 0, 0, 0)
        self.right_layout.setSpacing(0)

        # Topbar
        self.topbar = Topbar(self)
        self.right_layout.addWidget(self.topbar)

        # Stacked Pages
        self.stacked_widget = QStackedWidget(self)
        self.right_layout.addWidget(self.stacked_widget)
        self.main_layout.addWidget(self.right_container)

        # Instantiate Pages
        self.dashboard_page = DashboardPage(self)
        self.live_protection_page = LiveProtectionPage(self)
        self.threats_page = ThreatsPage(self.db, self)
        self.scan_page = ScanPage(self.db, self)
        self.reports_page = ReportsPage(self.db, self)
        self.history_page = HistoryPage(self.db, self)
        self.settings_page = SettingsPage(self.db, self)
        self.about_page = AboutPage(self)
        self.usb_page = USBProtectionPage(self.db, self)

        # Add to stack (Must match sidebar indexes)
        self.stacked_widget.addWidget(self.dashboard_page)       # Index 0
        self.stacked_widget.addWidget(self.live_protection_page) # Index 1
        self.stacked_widget.addWidget(self.threats_page)         # Index 2
        self.stacked_widget.addWidget(self.scan_page)            # Index 3
        self.stacked_widget.addWidget(self.reports_page)         # Index 4
        self.stacked_widget.addWidget(self.history_page)         # Index 5
        self.stacked_widget.addWidget(self.settings_page)        # Index 6
        self.stacked_widget.addWidget(self.about_page)           # Index 7
        self.stacked_widget.addWidget(self.usb_page)             # Index 8

        # Connect Navigation
        self.sidebar.page_changed.connect(self._change_page)
        self.dashboard_page.navigate_to_page.connect(self._navigate_stack_and_sidebar)
        if hasattr(self.dashboard_page, "investigate_incident"):
            self.dashboard_page.investigate_incident.connect(self._investigate_incident)
        if hasattr(self.scan_page, "investigate_incident"):
            self.scan_page.investigate_incident.connect(self._investigate_incident)
        
        # Connect settings page signals
        self.settings_page.protection_toggled.connect(self.topbar.update_protection_status)
        if hasattr(self.threats_page, "_update_protection_badge"):
            self.settings_page.protection_toggled.connect(lambda active: self.threats_page._update_protection_badge())
        self.settings_page.monitored_paths_changed.connect(self._on_monitored_paths_changed)

        # Connect threats page signals
        self.threats_page.incident_resolved.connect(self.dashboard_page.refresh)

        # Threaded Signals connection from EDR BatchProcessor
        self.batch_processor = self.monitor_manager.batch_processor
        self.batch_processor.events_processed.connect(self._on_events_processed)
        self.batch_processor.incident_detected.connect(self._on_incident_detected)
        self.batch_processor.stats_updated.connect(self._on_stats_updated)

        # Sync initial protection status (starts EDR monitoring threads if configured true)
        shield_active = self.settings_repo.get_setting("protection_enabled", "True").lower() == "true"
        self.topbar.update_protection_status(shield_active)
        # Dashboard is the default page — hide the topbar on startup
        self.topbar.setVisible(False)
        
        # Update monitored roots summary in dashboard
        paths = self.settings_repo.get_monitored_paths()
        self.dashboard_page.update_monitored_roots_summary(paths)
        
        # Start initial background file counting
        self.monitor_manager.start_file_counting(paths, self.dashboard_page.update_total_files)

        if shield_active:
            self.monitor_manager.start_monitoring()
        else:
            logger.info("EDR protection shield disabled at startup by settings.")

        # Existing File Scan Manager
        self.existing_scan_manager = ExistingScanManager.get_instance(self.db)
        self.existing_scan_manager.threat_detected.connect(lambda t: self.threats_page.refresh())

    def _center_on_screen(self):
        """Centers window on the user's primary display available workspace."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            x = geo.x() + max(0, (geo.width() - self.width()) // 2)
            y = geo.y() + max(0, (geo.height() - self.height()) // 2)
            self.move(x, y)

    def _change_page(self, index):
        """Switches stacked widgets page and updates topbar title."""
        self.stacked_widget.setCurrentIndex(index)
        page_titles = [
            "Dashboard Summary",
            "Real-time File Telemetry stream",
            "Security Threats repository",
            "Security Scan center",
            "Executive Reports & CSV Exports",
            "Administrative Audit Trail",
            "EDR Configurations & Protected partitions",
            "System Hardware & EDR Specifications",
            "Removable USB Storage Protection & Forensics"
        ]
        self.topbar.set_page_title(page_titles[index])

        # Hide topbar on Dashboard (0) and Threat Repository (2) — both provide integrated headers
        self.topbar.setVisible(index not in (0, 2))

        # Proactively refresh views when user navigates
        if index == 0:
            self.dashboard_page.refresh()
        elif index == 2:
            self.threats_page.refresh()
        elif index == 5:
            self.history_page.refresh()
        elif index == 6:
            self.settings_page.refresh_drives()
        elif index == 8:
            self.usb_page._refresh_device_view()


    def _navigate_stack_and_sidebar(self, index):
        """Allows page widgets to trigger navigation and align sidebar states."""
        self.sidebar.set_active_page(index)
        self._change_page(index)

    def _on_events_processed(self, events):
        """Passes batch events to Live Protection and refreshes History if currently visible."""
        self.live_protection_page.handle_new_events(events)
        if self.stacked_widget.currentIndex() == 5:
            self.history_page.refresh()

    def _on_stats_updated(self, stats):
        """Passes throttled database statistics to the dashboard page."""
        self.dashboard_page.update_statistics(stats)

    def _on_incident_detected(self, incident_data, is_new):
        """Triggers dashboard hero banners and refreshes threat listings."""
        self.threats_page.refresh()
        if is_new and hasattr(self.dashboard_page, "trigger_hero_alert"):
            self.dashboard_page.trigger_hero_alert(incident_data)

    def _investigate_incident(self, incident_id):
        """Switches to Threat Repository and automatically focuses on the requested incident."""
        self._navigate_stack_and_sidebar(2)  # Index 2 = Threats Page
        self.threats_page.navigate_to_incident(incident_id)

    def _on_monitored_paths_changed(self, paths):
        """Coordinates global EDR updates when the active drive protection scope changes."""
        # Invalidate database drive cache
        self.db.invalidate_active_drives_cache()

        # 1. Immediately place dashboard into analyzing loader state
        system_drive = os.environ.get("SystemDrive", "C:").rstrip(":").upper()
        drives_str = self.settings_repo.get_setting("protected_drives", system_drive)
        self.dashboard_page.set_analyzing_state(drives_str)

        # 2. Update the active watchdog observer monitor paths
        self.monitor_manager.update_monitoring_paths()
        
        # 3. Update dashboard paths listing
        self.dashboard_page.update_monitored_roots_summary(paths)
        
        # 4. Re-trigger background file counting
        self.monitor_manager.start_file_counting(paths, self.dashboard_page.update_total_files)
        
        # 5. Proactively refresh pages to filter telemetry and lists by the new scope
        self.live_protection_page.refresh()
        self.threats_page.refresh()
        self.history_page.refresh()

    def nativeEvent(self, event_type, message):
        """
        Intercepts Windows messages to detect USB insertion/removal dynamically.
        Uses native OS event loop instead of periodic polling.
        """
        if sys.platform.startswith("win") and event_type == b"windows_generic_MSG":
            msg = MSG.from_address(message.__int__())
            # 0x0219 is WM_DEVICECHANGE
            if msg.message == 0x0219:
                logger.info("Hardware device partition changed. Refreshing active drive map and USB devices.")
                # Triggers drives update on SettingsPage and USB Protection Manager
                self.settings_page.refresh_drives()
                if hasattr(self, "usb_page") and hasattr(self.usb_page, "usb_manager"):
                    self.usb_page.usb_manager.on_device_change()
                
        return super(MainWindow, self).nativeEvent(event_type, message)

    def closeEvent(self, event):
        """Safely shuts down background threads and DB connections upon exit."""
        logger.info("Application shutdown requested. Stopping monitors...")
        if hasattr(self, "existing_scan_manager"):
            self.existing_scan_manager.cancel_scan()
        self.monitor_manager.stop_monitoring()
        self.db.close_connection()
        event.accept()
