import os
import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame, 
    QFileDialog, QComboBox, QMessageBox
)
from PySide6.QtCore import Qt
from core.reporting.pdf_report import PDFReportGenerator
from core.reporting.csv_report import CSVReportGenerator
from core.database.database import DatabaseManager

class ReportsPage(QWidget):
    def __init__(self, db_manager=None, parent=None):
        super(ReportsPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # -------------------------------------------------------------
        # 1. Global Dataset Selection Card
        # -------------------------------------------------------------
        self.selector_card = QFrame(self)
        self.selector_card.setProperty("class", "metricCard")
        self.selector_layout = QVBoxLayout(self.selector_card)
        self.selector_layout.setSpacing(10)
        
        self.selector_title = QLabel("📋 SELECT REPORT TELEMETRY DATASET", self)
        self.selector_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px;")
        self.selector_layout.addWidget(self.selector_title)
        
        self.selector_row = QHBoxLayout()
        self.selector_lbl = QLabel("Target Data Table Source:", self)
        self.selector_lbl.setStyleSheet("color: #FFFFFF; font-size: 13px; font-weight: bold;")
        
        self.table_selector = QComboBox(self)
        self.table_selector.addItem("Executive Security Summary Report", "executive")
        self.table_selector.addItem("Security Incidents Logs", "incidents")
        self.table_selector.addItem("System File Events log", "events")
        self.table_selector.addItem("EDR Audit History logs", "history")
        self.table_selector.setMinimumWidth(260)
        
        self.selector_row.addWidget(self.selector_lbl)
        self.selector_row.addWidget(self.table_selector)
        self.selector_row.addStretch()
        self.selector_layout.addLayout(self.selector_row)
        
        self.main_layout.addWidget(self.selector_card)

        # -------------------------------------------------------------
        # 2. Executive PDF Card
        # -------------------------------------------------------------
        self.pdf_card = QFrame(self)
        self.pdf_card.setProperty("class", "metricCard")
        self.pdf_layout = QVBoxLayout(self.pdf_card)
        self.pdf_layout.setSpacing(10)

        self.pdf_title = QLabel("📄 EXECUTIVE SECURITY REPORT (PDF FORMAT)", self)
        self.pdf_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px;")
        self.pdf_layout.addWidget(self.pdf_title)

        self.pdf_desc = QLabel(
            "Generates a formal, printable PDF document summarizing records from the selected "
            "data table. Fits standard letter format, wrapping long values into structured grids.", 
            self
        )
        self.pdf_desc.setStyleSheet("color: #D1D5DB; font-size: 12px;")
        self.pdf_desc.setWordWrap(True)
        self.pdf_layout.addWidget(self.pdf_desc)

        # PDF Action row
        self.pdf_row = QHBoxLayout()
        self.generate_pdf_btn = QPushButton("Generate PDF Summary Report", self)
        self.generate_pdf_btn.setProperty("class", "primaryButton")
        self.generate_pdf_btn.setCursor(Qt.PointingHandCursor)
        self.pdf_row.addWidget(self.generate_pdf_btn)
        self.pdf_row.addStretch()
        self.pdf_layout.addLayout(self.pdf_row)

        self.main_layout.addWidget(self.pdf_card)

        # -------------------------------------------------------------
        # 3. CSV Data Export Card
        # -------------------------------------------------------------
        self.csv_card = QFrame(self)
        self.csv_card.setProperty("class", "metricCard")
        self.csv_layout = QVBoxLayout(self.csv_card)
        self.csv_layout.setSpacing(10)

        self.csv_title = QLabel("🗃️ TELEMETRY DATA EXPORTER (CSV FORMAT)", self)
        self.csv_title.setStyleSheet("font-weight: bold; color: #9CA3AF; font-size: 13px;")
        self.csv_layout.addWidget(self.csv_title)

        self.csv_desc = QLabel(
            "Exports raw database records from the selected data table directly to a comma-separated values (CSV) "
            "spreadsheet. Perfect for loading telemetry datasets into external spreadsheet or SIEM tools.", 
            self
        )
        self.csv_desc.setStyleSheet("color: #D1D5DB; font-size: 12px;")
        self.csv_desc.setWordWrap(True)
        self.csv_layout.addWidget(self.csv_desc)

        # CSV Configuration row
        self.csv_row = QHBoxLayout()
        self.export_csv_btn = QPushButton("Export Table to CSV", self)
        self.export_csv_btn.setProperty("class", "secondaryButton")
        self.export_csv_btn.setCursor(Qt.PointingHandCursor)
        self.csv_row.addWidget(self.export_csv_btn)
        self.csv_row.addStretch()
        self.csv_layout.addLayout(self.csv_row)

        self.main_layout.addWidget(self.csv_card)

        # -------------------------------------------------------------
        # 4. Progress / Status Frame
        # -------------------------------------------------------------
        self.status_card = QFrame(self)
        self.status_card.setProperty("class", "metricCard")
        self.status_card.setStyleSheet("background-color: #161B22; border-color: #3B82F6;")
        self.status_layout = QVBoxLayout(self.status_card)
        
        self.status_label = QLabel("Idle", self)
        self.status_label.setStyleSheet("color: #3B82F6; font-weight: 500;")
        self.status_layout.addWidget(self.status_label)
        
        self.main_layout.addWidget(self.status_card)
        self.status_card.setVisible(False)

        self.main_layout.addStretch()

        # Connect slots
        self.generate_pdf_btn.clicked.connect(self._generate_pdf)
        self.export_csv_btn.clicked.connect(self._export_csv)

        # Threads
        self.pdf_thread = None
        self.csv_thread = None

    def _generate_pdf(self):
        report_type = self.table_selector.currentData()
        default_name = f"RansomGuard_{report_type}_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Save PDF {self.table_selector.currentText()}", default_name, "PDF Files (*.pdf)"
        )
        
        if not file_path:
            return

        self._lock_ui(f"Generating PDF report for '{self.table_selector.currentText()}', please wait...")

        self.pdf_thread = PDFReportGenerator(file_path, report_type=report_type, db_manager=self.db)
        self.pdf_thread.finished.connect(self._on_pdf_completed)
        self.pdf_thread.error.connect(self._on_pdf_error)
        self.pdf_thread.start()

    def _on_pdf_completed(self, path):
        self._unlock_ui()
        try:
            if hasattr(os, "startfile"):
                os.startfile(path)
            else:
                from PySide6.QtGui import QDesktopServices
                from PySide6.QtCore import QUrl
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception:
            pass

        QMessageBox.information(
            self, "Report Generated",
            f"PDF security report successfully generated and opened:\n\n{path}"
        )

    def _on_pdf_error(self, err_msg):
        self._unlock_ui()
        QMessageBox.critical(
            self, "Generation Error",
            f"Failed to generate PDF report:\n\n{err_msg}"
        )

    def _export_csv(self):
        report_type = self.table_selector.currentData()
        if report_type == "executive":
            report_type = "incidents"
        default_name = f"RansomGuard_{report_type}_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Export {self.table_selector.currentText()} to CSV", default_name, "CSV Files (*.csv)"
        )
        
        if not file_path:
            return

        self._lock_ui(f"Exporting '{self.table_selector.currentText()}' table to CSV, please wait...")

        self.csv_thread = CSVReportGenerator(file_path, report_type=report_type, db_manager=self.db)
        self.csv_thread.finished.connect(self._on_csv_completed)
        self.csv_thread.error.connect(self._on_csv_error)
        self.csv_thread.start()

    def _on_csv_completed(self, path):
        self._unlock_ui()
        try:
            if hasattr(os, "startfile"):
                os.startfile(path)
            else:
                from PySide6.QtGui import QDesktopServices
                from PySide6.QtCore import QUrl
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception:
            pass

        QMessageBox.information(
            self, "CSV Export Successful",
            f"Data table successfully exported and opened:\n\n{path}"
        )

    def _on_csv_error(self, err_msg):
        self._unlock_ui()
        QMessageBox.critical(
            self, "Export Error",
            f"Failed to export CSV file:\n\n{err_msg}"
        )

    def _lock_ui(self, message):
        self.generate_pdf_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self.table_selector.setEnabled(False)
        
        self.status_label.setText(message)
        self.status_card.setVisible(True)

    def _unlock_ui(self):
        self.generate_pdf_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self.table_selector.setEnabled(True)
        self.status_card.setVisible(False)
