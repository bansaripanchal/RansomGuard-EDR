import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView, QLabel, QFrame, QHeaderView
from PySide6.QtCore import Qt, Signal, QEvent
from ui.components.tables import LiveEventsTableModel
from core.database.database import DatabaseManager

class LiveProtectionPage(QWidget):
    def __init__(self, parent=None):
        super(LiveProtectionPage, self).__init__(parent)
        self.db = DatabaseManager()
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # Controls row
        self.controls_layout = QHBoxLayout()
        
        self.status_label = QLabel("🟢 Real-Time Filesystem Monitoring Stream (Max 1,000 rolling events)", self)
        self.status_label.setStyleSheet("font-weight: bold; color: #9CA3AF;")
        self.controls_layout.addWidget(self.status_label)
        self.controls_layout.addStretch()

        # Pause and Clear buttons
        self.pause_btn = QPushButton("Pause Stream", self)
        self.pause_btn.setProperty("class", "secondaryButton")
        self.pause_btn.setCheckable(True)
        self.pause_btn.setCursor(Qt.PointingHandCursor)
        
        self.clear_btn = QPushButton("Clear View", self)
        self.clear_btn.setProperty("class", "secondaryButton")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        
        self.controls_layout.addWidget(self.pause_btn)
        self.controls_layout.addWidget(self.clear_btn)
        self.main_layout.addLayout(self.controls_layout)

        # Table View configuration
        self.table_view = QTableView(self)
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSelectionMode(QTableView.SingleSelection)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setAlternatingRowColors(True)
        
        # Load Model
        self.model = LiveEventsTableModel(max_rows=1000)
        self.table_view.setModel(self.model)

        # Set specific column widths (6 columns: Timestamp, Operation, Path, Description, Ext, File Size)
        self.table_view.setColumnWidth(0, 140) # Timestamp
        self.table_view.setColumnWidth(1, 80)  # Operation
        self.table_view.setColumnWidth(2, 320) # Path
        self.table_view.setColumnWidth(3, 180) # Description
        self.table_view.setColumnWidth(4, 65)  # Extension
        self.table_view.setColumnWidth(5, 95)  # Size (MB/GB)

        self.main_layout.addWidget(self.table_view)

        # Empty state label overlay
        self.empty_label = QLabel("No activity recorded.\nChoose directories to protect in the Settings tab.", self.table_view)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #9CA3AF; font-size: 14px; font-weight: 500;")
        
        # Hook layout resizing to center empty label
        self.table_view.installEventFilter(self)

        # Connect controls
        self.clear_btn.clicked.connect(self._clear_view)
        self.pause_btn.toggled.connect(self._toggle_pause)

        self.is_paused = False
        self.refresh()

    def refresh(self):
        """Pre-populates the table view with the latest real events from SQLite."""
        # Query active drives list
        drives = self.db.get_active_drives()
        drives_str = ", ".join(drives) if drives else "C:"
        
        self.status_label.setText(f"🟢 Real-Time Filesystem Monitoring Stream (Scope: {drives_str} | Max 1,000 rolling events)")
        self.status_label.setStyleSheet("font-weight: bold; color: #9CA3AF;")

        from core.database.events_repository import EventsRepository
        repo = EventsRepository(self.db)
        rows = repo.get_events(limit=500)
        events = [dict(r) for r in rows]
        
        self.model.clear()
        self.model.append_events(events)
        self._update_empty_state()

    def handle_new_events(self, events):
        """Appends events to table model in real-time, filtered by active drives."""
        if self.is_paused:
            return
            
        drives = self.db.get_active_drives()
        active_letters = {d.strip()[0].upper() for d in drives if d.strip()}
        filtered = []
        for ev in events:
            path = ev.get("src_path", "")
            if len(path) >= 2 and path[1] == ":":
                let = path[0].upper()
                if let in active_letters:
                    filtered.append(ev)
            else:
                filtered.append(ev)
                
        if filtered:
            self.model.append_events(filtered)
            self._update_empty_state()

    def _clear_view(self):
        self.model.clear()
        self._update_empty_state()

    def _toggle_pause(self, checked):
        self.is_paused = checked
        system_drive = os.environ.get("SystemDrive", "C:").rstrip(":").upper()
        drives_str = self.db.execute_read_one("SELECT value FROM settings WHERE key = 'protected_drives'")
        active_drives = drives_str["value"] if drives_str else system_drive
        
        if checked:
            self.pause_btn.setText("Resume Stream")
            self.status_label.setText(f"⏸️ Real-Time Filesystem Monitoring Stream (PAUSED | Scope: {active_drives})")
            self.status_label.setStyleSheet("font-weight: bold; color: #F59E0B;")
        else:
            self.pause_btn.setText("Pause Stream")
            self.status_label.setText(f"🟢 Real-Time Filesystem Monitoring Stream (Scope: {active_drives} | Max 1,000 rolling events)")
            self.status_label.setStyleSheet("font-weight: bold; color: #9CA3AF;")

    def _update_empty_state(self):
        if self.model.rowCount() == 0:
            self.empty_label.show()
        else:
            self.empty_label.hide()

    def eventFilter(self, obj, event):
        """Ensure empty state label stays centered inside the table viewport."""
        if obj == self.table_view and event.type() == QEvent.Resize:
            w = self.table_view.viewport().width()
            h = self.table_view.viewport().height()
            self.empty_label.setGeometry(0, 0, w, h)
        return super(LiveProtectionPage, self).eventFilter(obj, event)
