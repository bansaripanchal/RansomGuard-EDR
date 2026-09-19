import sys
import platform
import sqlite3
import psutil
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea
from PySide6.QtCore import Qt

class AboutPage(QWidget):
    def __init__(self, parent=None):
        super(AboutPage, self).__init__(parent)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Scroll area for clean reading of details
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(15)

        # 1. Product Brand & Objective
        brand_card = QFrame(self)
        brand_card.setProperty("class", "metricCard")
        brand_layout = QVBoxLayout(brand_card)
        brand_layout.setSpacing(8)

        title = QLabel("🛡️ RANSOMGUARD EDR (ENDPOINT DETECTION & RESPONSE)", self)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #3B82F6;")
        
        desc = QLabel(
            "RansomGuard is a lightweight, high-performance Endpoint Detection and Response (EDR) "
            "desktop agent designed specifically to defend against ransomware threats on Windows endpoints. "
            "It runs continuous filesystem telemetry monitoring, matches behavior heuristics, correlates file events "
            "to prevent alert fatigue, and reports system health status without impacting endpoint responsiveness.",
            self
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #FFFFFF; line-height: 1.4;")
        
        brand_layout.addWidget(title)
        brand_layout.addWidget(desc)
        scroll_layout.addWidget(brand_card)

        # 2. Real System Hardware Specifications (No fake values!)
        sys_card = QFrame(self)
        sys_card.setProperty("class", "metricCard")
        sys_layout = QVBoxLayout(sys_card)
        sys_layout.setSpacing(8)

        sys_title = QLabel("💻 ACTIVE ENDPOINT METADATA & SPECS", self)
        sys_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px; margin-bottom: 5px;")
        sys_layout.addWidget(sys_title)

        # Gather specifications
        total_ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        cpu_cores_logical = psutil.cpu_count(logical=True)
        cpu_cores_physical = psutil.cpu_count(logical=False)
        os_info = f"{platform.system()} {platform.release()} (v{platform.version()})"
        arch_info = platform.machine()
        py_version = sys.version.split(" ")[0]
        sqlite_version = sqlite3.sqlite_version

        specs = [
            (f"<b>Operating System</b>: {os_info}"),
            (f"<b>Architecture</b>: {arch_info}"),
            (f"<b>CPU Cores</b>: {cpu_cores_physical} Physical | {cpu_cores_logical} Logical"),
            (f"<b>Installed Memory (RAM)</b>: {total_ram} GB"),
            (f"<b>Python Compiler Environment</b>: v{py_version}"),
            (f"<b>SQLite Database Version</b>: v{sqlite_version}"),
        ]

        for s in specs:
            lbl = QLabel(s, self)
            lbl.setStyleSheet("font-family: Consolas, monospace; color: #D1D5DB; font-size: 12px;")
            sys_layout.addWidget(lbl)

        scroll_layout.addWidget(sys_card)

        # 3. Modular Architecture Details
        arch_card = QFrame(self)
        arch_card.setProperty("class", "metricCard")
        arch_layout = QVBoxLayout(arch_card)
        arch_layout.setSpacing(8)

        arch_title = QLabel("⚙️ EDR ENGINE ARCHITECTURE", self)
        arch_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px; margin-bottom: 5px;")
        arch_layout.addWidget(arch_title)

        engines = [
            ("📁 Real-Time Monitoring Engine", "Leverages a background filesystem listener using watchdog to capture CREATE, MODIFY, RENAME, and DELETE events in user-selected protected drives. Events are dispatched through a thread-safe queue to a batch processor for analysis."),
            ("🧠 Behavior Heuristics & Risk Engine", "Runs events through threshold rules (e.g. rapid creations/renames per sliding window) checking for typical ransomware-style indicators (e.g. suspicious extension transitions, ransom note creation). A dedicated RiskEngine assigns evidence-based risk scores and severity levels."),
            ("🔬 Unified File Analyzer", "Every file event, scheduled scan, and USB file passes through UnifiedFileAnalyzer — performing static analysis including SHA-256/MD5 hashing, entropy measurement, YARA rule matching, PE structure inspection, and extension/magic-byte validation."),
            ("🔗 Event Correlation", "Aggregates events in the same directory and time range to create a single correlated 'Incident' rather than flooding tables with thousands of individual alerts."),
            ("🗃️ Persistent WAL Storage", "Utilizes SQLite Write-Ahead Logging (WAL) and indexed tables to commit event bursts in transactions without blocking concurrent UI read operations."),
            ("🔍 Existing File Scan (Endpoint Discovery)", "Background scheduler enumerates all accessible files on protected drives, analyzing each through the Unified File Analyzer / Risk Engine pipeline. Supports Incremental (new/changed since last scan) and Full scan modes. Configurable frequency (hourly, daily, weekly, manual)."),
            ("💾 USB Protection", "Real-time USB device monitoring via Windows native event detection. When a USB drive is connected, the device is enumerated and every file is scanned through the full Unified File Analyzer pipeline before any user access."),
            ("🔍 Scan Center", "On-demand file and folder scanning. The user selects a file or directory and BackgroundScanner recursively analyzes files using the same Unified File Analyzer / Risk Engine pipeline as real-time protection."),
            ("🧵 Multi-Threaded Design", "Heavy operations — filesystem monitoring, file analysis, background scanning, USB enumeration, PDF compilation, and data exports — are delegated to dedicated QThread workers, preventing UI lockups."),
        ]

        for eng_title, eng_desc in engines:
            e_lbl = QLabel(f"<b>{eng_title}</b>", self)
            e_lbl.setStyleSheet("color: #3B82F6; font-size: 12px; margin-top: 5px;")
            d_lbl = QLabel(eng_desc, self)
            d_lbl.setStyleSheet("color: #D1D5DB; font-size: 12px;")
            d_lbl.setWordWrap(True)
            arch_layout.addWidget(e_lbl)
            arch_layout.addWidget(d_lbl)

        scroll_layout.addWidget(arch_card)
        scroll_layout.addStretch()

        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
