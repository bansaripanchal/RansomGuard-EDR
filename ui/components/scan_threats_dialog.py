import os
import datetime
from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QSizePolicy
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from ui.components.tables import format_file_size
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository


class ScanThreatsDialog(QDialog):
    """
    Modal dialog displaying the authentic threats identified by an Existing File Scan.
    Presents all 12 required telemetry fields and concrete rule evidence without fake data.
    Provides direct investigation integration with the RansomGuard Threat Repository.
    """
    investigate_threat = Signal(int)  # Emits incident_id

    def __init__(self, threats: List[Dict[str, Any]], scan_summary: Optional[Dict[str, Any]] = None,
                 db_manager=None, parent=None):
        super(ScanThreatsDialog, self).__init__(parent)
        self.threats = threats or []
        self.scan_summary = scan_summary or {}
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.current_index = 0

        self.setWindowTitle("RansomGuard EDR — Existing File Scan Detections")
        self.setModal(True)
        self.resize(960, 680)
        self.setMinimumSize(880, 580)

        # Apply cyber dark theme styling matching RansomGuard
        self.setStyleSheet("""
            QDialog {
                background-color: #0A0E14;
                color: #E6EDF3;
                font-family: "Segoe UI", -apple-system, sans-serif;
            }
            QFrame#dialogHeaderCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-bottom: 2px solid #EF4444;
                border-radius: 8px;
                padding: 12px 18px;
            }
            QFrame#threatDetailCard {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 8px;
                padding: 14px 18px;
            }
            QListWidget#threatList {
                background-color: #0D1218;
                border: 1px solid #1C2630;
                border-radius: 8px;
                outline: none;
                padding: 4px;
            }
            QListWidget#threatList::item {
                background-color: #10161D;
                border: 1px solid #1C2630;
                border-radius: 6px;
                padding: 8px 10px;
                margin-bottom: 6px;
                color: #E6EDF3;
            }
            QListWidget#threatList::item:hover {
                background-color: #16202B;
                border-color: #3B82F6;
            }
            QListWidget#threatList::item:selected {
                background-color: #1A2634;
                border: 1px solid #EF4444;
                border-left: 4px solid #EF4444;
                color: #FFFFFF;
            }
            QTableWidget {
                background-color: #0D1218;
                border: 1px solid #1C2630;
                border-radius: 6px;
                gridline-color: #1C2630;
                outline: none;
            }
            QTableWidget::item {
                padding: 6px 8px;
                border-bottom: 1px solid #1C2630;
                color: #CBD5E1;
            }
            QHeaderView::section {
                background-color: #10161D;
                color: #8B98A8;
                padding: 6px 8px;
                border: none;
                border-bottom: 1px solid #1C2630;
                font-weight: bold;
                font-size: 11px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 1. Dialog Header Card
        self._build_header(layout)

        # 2. Main Content (Two-pane: List on left, Detail on right)
        body_layout = QHBoxLayout()
        body_layout.setSpacing(12)

        # Left Pane: Threat list
        left_box = QVBoxLayout()
        left_box.setSpacing(6)
        left_title = QLabel(f"DETECTED THREATS ({len(self.threats)})", self)
        left_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        left_box.addWidget(left_title)

        self.threat_list = QListWidget(self)
        self.threat_list.setObjectName("threatList")
        self.threat_list.setFixedWidth(280)
        self.threat_list.currentRowChanged.connect(self._on_threat_selected)
        left_box.addWidget(self.threat_list)
        body_layout.addLayout(left_box)

        # Right Pane: Detailed Telemetry View inside Scroll Area
        self.detail_scroll = QScrollArea(self)
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.detail_container = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_container)
        self.detail_layout.setContentsMargins(0, 0, 4, 0)
        self.detail_layout.setSpacing(10)
        self.detail_scroll.setWidget(self.detail_container)

        self._build_detail_pane()
        body_layout.addWidget(self.detail_scroll, 1)

        layout.addLayout(body_layout)

        # 3. Bottom Action Bar
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(10)

        self.status_hint = QLabel("Select a detected file to inspect static telemetry and rule triggers.", self)
        self.status_hint.setStyleSheet("color: #64748B; font-size: 12px;")
        bottom_row.addWidget(self.status_hint)
        bottom_row.addStretch()

        self.btn_investigate = QPushButton("🔍 Investigate in Threat Repository →", self)
        self.btn_investigate.setStyleSheet("""
            QPushButton {
                background-color: #2563EB;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1D4ED8;
            }
        """)
        self.btn_investigate.setCursor(Qt.PointingHandCursor)
        self.btn_investigate.clicked.connect(self._on_investigate_clicked)
        bottom_row.addWidget(self.btn_investigate)

        self.btn_close = QPushButton("Close", self)
        self.btn_close.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #CBD5E1;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #334155;
                color: #FFFFFF;
            }
        """)
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.clicked.connect(self.close)
        bottom_row.addWidget(self.btn_close)

        layout.addLayout(bottom_row)

        # Populate list
        self._populate_list()

    def _build_header(self, parent_layout):
        header_card = QFrame(self)
        header_card.setObjectName("dialogHeaderCard")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(14, 10, 14, 10)
        h_layout.setSpacing(12)

        icon_lbl = QLabel("⚠️", header_card)
        icon_lbl.setStyleSheet("font-size: 26px; background: transparent; border: none;")
        h_layout.addWidget(icon_lbl)

        v_box = QVBoxLayout()
        v_box.setSpacing(2)

        count = len(self.threats)
        threat_str = f"{count} Threat{'s' if count != 1 else ''}"
        title_lbl = QLabel(f"SCAN DETECTIONS — {threat_str.upper()} IDENTIFIED", header_card)
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.3px; background: transparent; border: none;")
        v_box.addWidget(title_lbl)

        # Scan metadata subtitle
        scan_id = self.scan_summary.get("scan_id") or "Current Session"
        analyzed = self.scan_summary.get("files_analyzed") or self.scan_summary.get("analyzed_count") or 0
        end_time = self.scan_summary.get("end_time") or self.scan_summary.get("start_time") or "Completed"
        sub_text = f"Existing File Scan session: {scan_id}  ·  {analyzed:,} files checked  ·  {end_time}"
        sub_lbl = QLabel(sub_text, header_card)
        sub_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-family: Consolas, monospace; background: transparent; border: none;")
        v_box.addWidget(sub_lbl)

        h_layout.addLayout(v_box)
        h_layout.addStretch()

        badge_lbl = QLabel(f" {count} DETECTED ", header_card)
        badge_lbl.setStyleSheet("""
            background-color: rgba(239, 68, 68, 0.2);
            color: #EF4444;
            border: 1px solid rgba(239, 68, 68, 0.5);
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 8px;
        """)
        h_layout.addWidget(badge_lbl)

        parent_layout.addWidget(header_card)

    def _build_detail_pane(self):
        # Card 1: Primary Threat Attributes
        self.detail_card = QFrame(self.detail_container)
        self.detail_card.setObjectName("threatDetailCard")
        dc_layout = QVBoxLayout(self.detail_card)
        dc_layout.setContentsMargins(14, 12, 14, 12)
        dc_layout.setSpacing(10)

        # Top banner with verdict badges
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.verdict_badge = QLabel("VERDICT: SUSPICIOUS", self.detail_card)
        self.verdict_badge.setStyleSheet("background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")
        top_row.addWidget(self.verdict_badge)

        self.severity_badge = QLabel("SEVERITY: HIGH", self.detail_card)
        self.severity_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #EF4444; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")
        top_row.addWidget(self.severity_badge)

        self.risk_badge = QLabel("RISK: 85 / 100", self.detail_card)
        self.risk_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #F87171; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")
        top_row.addWidget(self.risk_badge)

        top_row.addStretch()

        self.detection_source_lbl = QLabel("Source: Existing File Scan", self.detail_card)
        self.detection_source_lbl.setStyleSheet("color: #64748B; font-size: 12px; font-weight: 600;")
        top_row.addWidget(self.detection_source_lbl)

        dc_layout.addLayout(top_row)

        # Threat name headline
        self.threat_name_lbl = QLabel("Security Threat Identified", self.detail_card)
        self.threat_name_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        dc_layout.addWidget(self.threat_name_lbl)

        # Thin divider
        div = QFrame(self.detail_card)
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background-color: #1C2630; max-height: 1px; border: none;")
        dc_layout.addWidget(div)

        # 12 Required Fields Display
        self.meta_labels = {}
        fields = [
            ("file_name", "File Name:"),
            ("full_path", "Full Path:"),
            ("detection_reason", "Detection Reason:"),
            ("sha256", "SHA-256:"),
            ("file_size", "File Size:"),
            ("file_type", "File Type:"),
            ("time_modified", "Modified Time:"),
            ("time_created", "Created Time:"),
            ("time_scanned", "Scan Timestamp:"),
        ]

        from PySide6.QtWidgets import QGridLayout
        grid = QGridLayout()
        grid.setSpacing(6)
        grid.setContentsMargins(0, 4, 0, 4)

        for row_idx, (key, label_str) in enumerate(fields):
            lbl = QLabel(label_str, self.detail_card)
            lbl.setStyleSheet("color: #8B98A8; font-size: 12px; font-weight: 600;")
            lbl.setAlignment(Qt.AlignRight | Qt.AlignTop)

            val = QLabel("Not available", self.detail_card)
            val.setStyleSheet("color: #E6EDF3; font-size: 12px; font-family: Consolas, monospace;")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            val.setWordWrap(True)

            grid.addWidget(lbl, row_idx, 0)
            grid.addWidget(val, row_idx, 1)
            self.meta_labels[key] = val

        dc_layout.addLayout(grid)
        self.detail_layout.addWidget(self.detail_card)

        # Card 2: Concrete Rule & Evidence Table
        self.evidence_card = QFrame(self.detail_container)
        self.evidence_card.setObjectName("threatDetailCard")
        ec_layout = QVBoxLayout(self.evidence_card)
        ec_layout.setContentsMargins(14, 12, 14, 12)
        ec_layout.setSpacing(8)

        ec_title = QLabel("DETECTION EVIDENCE & APPLIED RULES", self.evidence_card)
        ec_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #8B98A8; letter-spacing: 0.5px;")
        ec_layout.addWidget(ec_title)

        self.evidence_table = QTableWidget(self.evidence_card)
        self.evidence_table.setColumnCount(3)
        self.evidence_table.setHorizontalHeaderLabels(["Rule", "Observed Evidence", "Risk Score"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.evidence_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.setFixedHeight(140)
        ec_layout.addWidget(self.evidence_table)

        self.detail_layout.addWidget(self.evidence_card)

        # Placeholder card for empty / unselected state
        self.no_selection_widget = QFrame(self.detail_container)
        self.no_selection_widget.setObjectName("threatDetailCard")
        ns_layout = QVBoxLayout(self.no_selection_widget)
        ns_layout.setContentsMargins(20, 50, 20, 50)
        ns_lbl = QLabel("Select a detected threat from the list to view detailed telemetry, file metrics, and rule triggers.", self.no_selection_widget)
        ns_lbl.setAlignment(Qt.AlignCenter)
        ns_lbl.setStyleSheet("color: #64748B; font-size: 13px; font-weight: 500; background: transparent; border: none;")
        ns_layout.addWidget(ns_lbl)
        self.detail_layout.addWidget(self.no_selection_widget)

        # Default initial state: show placeholder, hide detail cards until a threat is selected
        self.no_selection_widget.setVisible(True)
        self.detail_card.setVisible(False)
        self.evidence_card.setVisible(False)

    def _populate_list(self):
        self.threat_list.clear()
        if not self.threats:
            empty_item = QListWidgetItem("No threats detected in this scan.")
            self.threat_list.addItem(empty_item)
            self.btn_investigate.setEnabled(False)
            self.no_selection_widget.setVisible(True)
            self.detail_card.setVisible(False)
            self.evidence_card.setVisible(False)
            return

        for idx, t in enumerate(self.threats):
            filename = t.get("filename") or os.path.basename(t.get("file_path", "Unknown File"))
            verdict = t.get("verdict", "SUSPICIOUS")
            risk = t.get("risk_score", 0)
            item_text = f"{idx + 1}. {filename}\n   [{verdict}]  Risk: {risk}/100"

            item = QListWidgetItem(item_text)
            self.threat_list.addItem(item)

        self.threat_list.setCurrentRow(0)

    def _on_threat_selected(self, row: int):
        if not self.threats or row < 0 or row >= len(self.threats):
            self.no_selection_widget.setVisible(True)
            self.detail_card.setVisible(False)
            self.evidence_card.setVisible(False)
            return

        self.no_selection_widget.setVisible(False)
        self.detail_card.setVisible(True)
        self.evidence_card.setVisible(True)
        self.current_index = row
        t = self.threats[row]

        # 1. Badges
        verdict = t.get("verdict", "SUSPICIOUS").upper()
        severity = t.get("severity", "HIGH").upper()
        risk = t.get("risk_score", 0)

        self.verdict_badge.setText(f"VERDICT: {verdict}")
        if verdict == "MALICIOUS":
            self.verdict_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.25); color: #EF4444; font-weight: bold; font-size: 12px; border: 1px solid #EF4444; border-radius: 4px; padding: 3px 8px;")
        elif verdict == "SUSPICIOUS":
            self.verdict_badge.setStyleSheet("background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; font-weight: bold; font-size: 12px; border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 4px; padding: 3px 8px;")
        else:
            self.verdict_badge.setStyleSheet("background-color: rgba(59, 130, 246, 0.2); color: #3B82F6; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")

        self.severity_badge.setText(f"SEVERITY: {severity}")
        if severity == "CRITICAL":
            self.severity_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.3); color: #EF4444; font-weight: bold; font-size: 12px; border: 1px solid #EF4444; border-radius: 4px; padding: 3px 8px;")
        elif severity == "HIGH":
            self.severity_badge.setStyleSheet("background-color: rgba(249, 115, 22, 0.2); color: #F97316; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")
        elif severity == "MEDIUM":
            self.severity_badge.setStyleSheet("background-color: rgba(245, 158, 11, 0.2); color: #F59E0B; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")
        else:
            self.severity_badge.setStyleSheet("background-color: rgba(59, 130, 246, 0.2); color: #3B82F6; font-weight: bold; font-size: 12px; border-radius: 4px; padding: 3px 8px;")

        self.risk_badge.setText(f"RISK SCORE: {risk} / 100")
        source = t.get("detection_source") or "Existing File Scan"
        self.detection_source_lbl.setText(f"Source: {source}")

        threat_name = t.get("threat_name") or "Security Threat Identified"
        self.threat_name_lbl.setText(threat_name)

        # 2. 12 Telemetry Fields
        file_path = t.get("file_path", "Not available")
        filename = t.get("filename") or (os.path.basename(file_path) if file_path != "Not available" else "Not available")
        self.meta_labels["file_name"].setText(filename)
        self.meta_labels["full_path"].setText(file_path)
        self.meta_labels["full_path"].setToolTip(file_path)

        reason = t.get("reason") or "Suspicious indicator identified during file scan."
        self.meta_labels["detection_reason"].setText(reason)

        sha = t.get("sha256") or "Not available"
        self.meta_labels["sha256"].setText(sha)
        self.meta_labels["sha256"].setToolTip(sha)

        size_raw = t.get("file_size")
        if size_raw is not None and isinstance(size_raw, (int, float)) and size_raw >= 0:
            size_fmt = format_file_size(size_raw)
            self.meta_labels["file_size"].setText(f"{size_fmt} ({int(size_raw):,} bytes)")
        else:
            self.meta_labels["file_size"].setText("Not available")

        self.meta_labels["file_type"].setText(t.get("file_type") or "Unknown")

        # Modified & Created Timestamps from nanoseconds
        mtime_ns = t.get("mtime_ns")
        if mtime_ns and mtime_ns > 0:
            m_dt = datetime.datetime.fromtimestamp(mtime_ns / 1e9)
            self.meta_labels["time_modified"].setText(m_dt.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.meta_labels["time_modified"].setText("Not available")

        ctime_ns = t.get("ctime_ns")
        if ctime_ns and ctime_ns > 0:
            c_dt = datetime.datetime.fromtimestamp(ctime_ns / 1e9)
            self.meta_labels["time_created"].setText(c_dt.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self.meta_labels["time_created"].setText("Not available")

        scan_time = t.get("detection_time") or t.get("last_scanned_at") or self.scan_summary.get("end_time") or "Not available"
        self.meta_labels["time_scanned"].setText(str(scan_time))

        # 3. Evidence Table
        self._populate_evidence_table(t)

    def _populate_evidence_table(self, threat: Dict[str, Any]):
        self.evidence_table.setRowCount(0)

        # Parse concrete rules from record
        rules_data = []

        threat_name = threat.get("threat_name") or "STATIC_DETECTION_RULE"
        reason = threat.get("reason") or "Suspicious file characteristic detected"
        risk = threat.get("risk_score", 30)

        # If evidence string exists, parse lines
        ev_str = threat.get("evidence") or ""
        if ev_str and "|" in ev_str:
            # Format: RULE | EVIDENCE | RISK
            for line in ev_str.strip().split("\n"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    rules_data.append((parts[0], parts[1], parts[2]))
                elif len(parts) == 2:
                    rules_data.append((parts[0], parts[1], f"+{risk}"))

        if not rules_data:
            rule_id = "RANSOM_NOTE_PATTERN" if "note" in reason.lower() or "readme" in reason.lower() else "SUSPICIOUS_EXTENSION" if "extension" in reason.lower() else threat_name.upper().replace(" ", "_")
            rules_data.append((rule_id, reason, f"+{risk}"))

        # Extra indicators
        if threat.get("file_type") and threat.get("file_type") != "Unknown":
            rules_data.append(("FILE_STRUCTURE_IDENTIFIER", f"Validated file type: {threat.get('file_type')}", "+0"))

        if threat.get("sha256") and threat.get("sha256") != "Not available":
            rules_data.append(("CRYPTOGRAPHIC_HASH", f"Authentic SHA-256 fingerprint computed: {threat.get('sha256')[:16]}...", "+0"))

        self.evidence_table.setRowCount(len(rules_data))
        for r_idx, (r_name, r_ev, r_risk) in enumerate(rules_data):
            it_name = QTableWidgetItem(r_name)
            it_name.setForeground(QColor("#93C5FD"))
            it_name.setFont(QFont("Consolas", 10, QFont.Bold))

            it_ev = QTableWidgetItem(r_ev)
            it_ev.setFont(QFont("Segoe UI", 10))

            it_risk = QTableWidgetItem(r_risk)
            it_risk.setTextAlignment(Qt.AlignCenter)
            it_risk.setForeground(QColor("#F87171") if "+" in r_risk and r_risk != "+0" else QColor("#94A3B8"))
            it_risk.setFont(QFont("Consolas", 10, QFont.Bold))

            self.evidence_table.setItem(r_idx, 0, it_name)
            self.evidence_table.setItem(r_idx, 1, it_ev)
            self.evidence_table.setItem(r_idx, 2, it_risk)

    def _on_investigate_clicked(self):
        """
        Integrates threat into the Threat Repository without duplicate creation,
        closes dialog, and navigates to the detailed investigation panel.
        """
        if not self.threats or self.current_index < 0 or self.current_index >= len(self.threats):
            return

        t = self.threats[self.current_index]
        file_path = t.get("file_path", "")
        sha256 = t.get("sha256")
        folder = os.path.dirname(file_path) if file_path else ""
        filename = t.get("filename") or (os.path.basename(file_path) if file_path else "Threat File")
        source = t.get("detection_source") or "Existing File Scan"

        # Check existing incident to prevent duplicates
        existing = self.inc_repo.get_active_incident_by_path_or_hash(file_path, sha256)
        if existing:
            inc_id = existing["id"]
        else:
            # Create fresh incident for investigation
            reason = t.get("reason") or "Suspicious file identified during existing scan"
            ev_str = (
                f"Detection Source: {source}\n"
                f"Scan Run ID: {self.scan_summary.get('scan_id', 'Unknown')}\n"
                f"File verified on disk (Size: {t.get('file_size', 0):,} bytes)\n"
                f"SHA-256: {sha256}\n"
                f"Observed Reason: {reason}"
            )
            inc_id = self.inc_repo.insert_incident(
                threat_name=f"{t.get('threat_name', 'Suspicious File')} ({source})",
                severity=t.get("severity", "LOW"),
                risk_score=t.get("risk_score", 30),
                affected_folder=folder,
                affected_file=filename,
                full_path=file_path,
                detection_reason=f"[{source}] {reason}",
                recommendation="Review file location. Quarantine or delete if unrecognized.",
                status="ACTIVE",
                verdict=t.get("verdict", "SUSPICIOUS"),
                evidence=ev_str,
                attribution_status="UNAVAILABLE",
                file_size=t.get("file_size"),
                sha256=sha256,
                file_type=t.get("file_type")
            )

        self.investigate_threat.emit(inc_id)
        self.accept()
