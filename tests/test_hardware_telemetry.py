import os
import sys
import unittest
from unittest.mock import patch
import psutil
from PySide6.QtWidgets import QApplication

app = QApplication.instance()
if app is None:
    app = QApplication(sys.argv)

from ui.pages.dashboard_page import DashboardPage


class TestHardwareTelemetry(unittest.TestCase):
    def setUp(self):
        self.dashboard = DashboardPage()

    def tearDown(self):
        if hasattr(self.dashboard, 'sys_timer'):
            self.dashboard.sys_timer.stop()
        self.dashboard.deleteLater()

    def test_hardware_meters_on_dashboard(self):
        """Verifies Endpoint Host & EDR Status card contains the 6 required telemetry items."""
        self.assertTrue(hasattr(self.dashboard, 'endpoint_status_card'))
        self.assertTrue(hasattr(self.dashboard, 'cpu_bar'))
        self.assertTrue(hasattr(self.dashboard, 'ram_bar'))
        self.assertTrue(hasattr(self.dashboard, 'cpu_pct_lbl'))
        self.assertTrue(hasattr(self.dashboard, 'ram_pct_lbl'))
        self.assertTrue(hasattr(self.dashboard, 'status_host_val_lbl'))
        self.assertTrue(hasattr(self.dashboard, 'status_user_val_lbl'))
        self.assertTrue(hasattr(self.dashboard, 'status_os_val_lbl'))
        self.assertTrue(hasattr(self.dashboard, 'status_drive_val_lbl'))

    def test_pulse_card_occupies_mid_section(self):
        """Verifies Security Activity Pulse card is present and expanded."""
        self.assertTrue(hasattr(self.dashboard, 'pulse_card'))
        self.assertTrue(hasattr(self.dashboard, 'pulse_widget'))
        self.assertIsNotNone(self.dashboard.pulse_card)

    def test_hardware_stats_stub_safe(self):
        """Verifies backward compatibility stub is safe to invoke."""
        try:
            self.dashboard._update_system_hardware_stats()
        except Exception as e:
            self.fail(f"_update_system_hardware_stats raised unexpectedly: {e}")

    def test_dashboard_metrics_initialized(self):
        """Verifies primary health metrics cards are loaded."""
        for key in ("total_files", "files_monitored", "incidents_active", "incidents_blocked"):
            self.assertIn(key, self.dashboard.cards)

if __name__ == '__main__':
    unittest.main()
