from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView, QLabel, QFrame, QHeaderView
)
from PySide6.QtCore import Qt, QEvent
from ui.components.tables import HistoryTableModel
from core.database.history_repository import HistoryRepository
from core.database.database import DatabaseManager

class HistoryPage(QWidget):
    def __init__(self, db_manager=None, parent=None):
        super(HistoryPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.history_repo = HistoryRepository(self.db)
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # Control Row
        self.controls_layout = QHBoxLayout()
        self.title_label = QLabel("🕒 Audit Trail Security Logs", self)
        self.title_label.setStyleSheet("font-weight: bold; color: #9CA3AF;")
        self.controls_layout.addWidget(self.title_label)
        self.controls_layout.addStretch()

        self.clear_btn = QPushButton("🧹 Clear Audit Logs", self)
        self.clear_btn.setProperty("class", "secondaryButton")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.controls_layout.addWidget(self.clear_btn)
        
        self.main_layout.addLayout(self.controls_layout)

        # Table View
        self.table_view = QTableView(self)
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSelectionMode(QTableView.SingleSelection)
        self.table_view.setEditTriggers(QTableView.NoEditTriggers)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setAlternatingRowColors(True)

        self.model = HistoryTableModel()
        self.table_view.setModel(self.model)

        # Proportional column sizing with Description stretching dynamically
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table_view.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch) # Description
        
        self.table_view.setColumnWidth(0, 155) # Timestamp
        self.table_view.setColumnWidth(1, 140) # Event Type
        self.table_view.setColumnWidth(2, 75)  # Severity
        self.table_view.setColumnWidth(4, 180) # Target (Monitored Path/Setting Key)
        self.table_view.setColumnWidth(5, 160) # Action Taken

        self.main_layout.addWidget(self.table_view)

        # Pagination controls
        self.pager_layout = QHBoxLayout()
        self.pager_layout.addStretch()
        
        self.prev_btn = QPushButton("◀️ Prev", self)
        self.prev_btn.setProperty("class", "secondaryButton")
        self.prev_btn.setCursor(Qt.PointingHandCursor)
        
        self.page_info_label = QLabel("Page 1 of 1", self)
        self.page_info_label.setStyleSheet("color: #FFFFFF; font-weight: bold; padding: 0 10px;")
        
        self.next_btn = QPushButton("Next ▶️", self)
        self.next_btn.setProperty("class", "secondaryButton")
        self.next_btn.setCursor(Qt.PointingHandCursor)

        self.pager_layout.addWidget(self.prev_btn)
        self.pager_layout.addWidget(self.page_info_label)
        self.pager_layout.addWidget(self.next_btn)
        self.pager_layout.addStretch()
        
        self.main_layout.addLayout(self.pager_layout)

        # Empty state label
        self.empty_label = QLabel("No activity recorded yet.", self.table_view)
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #9CA3AF; font-size: 13px; font-weight: 500;")
        self.table_view.installEventFilter(self)

        # Connect controls
        self.clear_btn.clicked.connect(self._clear_logs)
        self.prev_btn.clicked.connect(self._prev_page)
        self.next_btn.clicked.connect(self._next_page)

        self.current_page = 0
        self.page_size = 50
        self.refresh()

    def refresh(self):
        """Fetches history records from database with paging."""
        total_records = self.history_repo.get_total_logs_count()
        max_page = max(0, (total_records - 1) // self.page_size)
        
        # Guard current page bounds
        if self.current_page > max_page:
            self.current_page = max_page
        if self.current_page < 0:
            self.current_page = 0

        # Query database
        offset = self.current_page * self.page_size
        rows = self.history_repo.get_logs(limit=self.page_size, offset=offset)
        logs = [dict(r) for r in rows]
        
        self.model.set_logs(logs)

        # Update page label
        display_page = self.current_page + 1
        display_max = max(1, max_page + 1)
        self.page_info_label.setText(f"Page {display_page} of {display_max}")

        # Enable/Disable buttons
        self.prev_btn.setEnabled(self.current_page > 0)
        self.next_btn.setEnabled(self.current_page < max_page)

        self._update_empty_state()

    def _clear_logs(self):
        self.history_repo.clear_history()
        self.current_page = 0
        self.refresh()

    def _prev_page(self):
        self.current_page -= 1
        self.refresh()

    def _next_page(self):
        self.current_page += 1
        self.refresh()

    def _update_empty_state(self):
        if self.model.rowCount() == 0:
            self.empty_label.show()
        else:
            self.empty_label.hide()

    def eventFilter(self, obj, event):
        if obj == self.table_view and event.type() == QEvent.Resize:
            w = self.table_view.viewport().width()
            h = self.table_view.viewport().height()
            self.empty_label.setGeometry(0, 0, w, h)
        return super(HistoryPage, self).eventFilter(obj, event)
