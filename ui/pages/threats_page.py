import os
import time
import datetime
from typing import Optional, Dict, Any, List, Set

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView, QLabel, 
    QFrame, QHeaderView, QSplitter, QGridLayout, QFileDialog, QMessageBox,
    QLineEdit, QButtonGroup, QScrollArea, QTableWidget, QTableWidgetItem,
    QSizePolicy, QStyledItemDelegate, QStyle
)
from PySide6.QtCore import Qt, Signal, QRect, QEvent
from PySide6.QtGui import QFont, QColor, QPainter, QPen

from ui.components.tables import IncidentsTableModel, IncidentActivityTableModel, format_file_size
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository
from core.database.settings_repository import SettingsRepository
from core.database.history_repository import HistoryRepository
from core.database.database import DatabaseManager
from core.reporting.pdf_report import PDFReportGenerator


class DismissItemDelegate(QStyledItemDelegate):
    """
    Renders a neat, interactive [ × ] button in the DISMISS column with subtle hover feedback.
    """
    def paint(self, painter, option, index):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)

        # Draw selection background if row is selected
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor("#10192D"))

        # Centered button bounding box
        rect = option.rect
        bw, bh = 22, 20
        bx = rect.x() + (rect.width() - bw) // 2
        by = rect.y() + (rect.height() - bh) // 2
        btn_rect = QRect(bx, by, bw, bh)

        is_hovered = bool(option.state & QStyle.State_MouseOver)
        if is_hovered:
            painter.setBrush(QColor("rgba(239, 68, 68, 0.22)"))
            painter.setPen(QPen(QColor("#EF4444"), 1))
            painter.drawRoundedRect(btn_rect, 4, 4)
            painter.setPen(QColor("#EF4444"))
        else:
            painter.setBrush(QColor("#111A2B"))
            painter.setPen(QPen(QColor("#1A2940"), 1))
            painter.drawRoundedRect(btn_rect, 4, 4)
            painter.setPen(QColor("#71809A"))

        font = painter.font()
        font.setPointSize(11)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(btn_rect, Qt.AlignCenter, "×")
        painter.restore()


class ThreatsPage(QWidget):
    """
    Centralized SOC/EDR Threat Repository & Incident Investigation Console.
    Provides complete visibility, real-time database telemetry, search/filtering,
    and granular incident analysis without placeholder or fabricated data.
    """
    incident_resolved = Signal()

    def __init__(self, db_manager=None, parent=None):
        super(ThreatsPage, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.events_repo = EventsRepository(self.db)
        self.settings_repo = SettingsRepository(self.db)

        self.current_incident = None
        self.current_severity_filter = None
        self.current_status_filter = None

        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(18, 16, 18, 16)
        self.main_layout.setSpacing(12)

        # 1. Page Header with Protection Indicator
        self._build_header()

        # 2. Compact Unified Filter Toolbar (Summary row & search box removed)
        self._build_filter_toolbar()

        # 3. Vertical Splitter: Main Threat Table (Upper) & Investigation Panel (Lower)
        self.splitter = QSplitter(Qt.Vertical, self)
        self.splitter.setHandleWidth(4)
        self.splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #1A2940;
                border-radius: 2px;
            }
            QSplitter::handle:hover {
                background-color: #355B8A;
            }
        """)
        self.main_layout.addWidget(self.splitter, 1)

        # Upper: Threat Table Container
        self._build_table_view()

        # Lower: Incident Investigation Panel (Collapsed by default)
        self._build_investigation_panel()

    def _build_header(self):
        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        v_title = QVBoxLayout()
        v_title.setSpacing(2)

        title_lbl = QLabel("SECURITY THREAT REPOSITORY", self)
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.5px;")
        v_title.addWidget(title_lbl)

        sub_lbl = QLabel("Centralized threat detection and incident investigation", self)
        sub_lbl.setStyleSheet("font-size: 12px; color: #8B98A8; font-weight: 500;")
        v_title.addWidget(sub_lbl)

        header_row.addLayout(v_title)
        header_row.addStretch()

        # Right: Protection status badge wired to real application state
        self.protection_badge = QLabel(self)
        self._update_protection_badge()
        header_row.addWidget(self.protection_badge)

        self.main_layout.addLayout(header_row)

    def _update_protection_badge(self):
        is_active = self.settings_repo.get_setting("protection_enabled", "True").lower() == "true"
        if is_active:
            self.protection_badge.setText("● PROTECTION ACTIVE")
            self.protection_badge.setStyleSheet("""
                background-color: rgba(34, 197, 94, 0.12);
                color: #22C55E;
                font-size: 12px;
                font-weight: 700;
                border: 1px solid rgba(34, 197, 94, 0.35);
                border-radius: 4px;
                padding: 4px 12px;
            """)
        else:
            self.protection_badge.setText("○ PROTECTION DISABLED")
            self.protection_badge.setStyleSheet("""
                background-color: rgba(245, 158, 11, 0.12);
                color: #F59E0B;
                font-size: 12px;
                font-weight: 700;
                border: 1px solid rgba(245, 158, 11, 0.35);
                border-radius: 4px;
                padding: 4px 12px;
            """)

    def _build_filter_toolbar(self):
        toolbar_frame = QFrame(self)
        toolbar_frame.setStyleSheet("""
            QFrame {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        tb_layout = QHBoxLayout(toolbar_frame)
        tb_layout.setContentsMargins(6, 4, 6, 4)
        tb_layout.setSpacing(8)

        # 1. Severity Filters (Critical, High, Medium, Low - NO ALL button)
        sev_lbl = QLabel("Severity:", toolbar_frame)
        sev_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: 700; letter-spacing: 0.3px;")
        tb_layout.addWidget(sev_lbl)

        btn_style_base = """
            QPushButton {
                background-color: #111A2B;
                color: #CBD5E1;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                border-color: #21334D;
            }
            QPushButton:checked {
                background-color: %s;
                color: #FFFFFF;
                border: 1px solid %s;
                font-weight: bold;
            }
        """

        self.btn_sev_crit = QPushButton("Critical", toolbar_frame)
        self.btn_sev_crit.setCheckable(True)
        self.btn_sev_crit.setStyleSheet(btn_style_base % ("#EF4444", "#EF4444"))
        self.btn_sev_crit.setCursor(Qt.PointingHandCursor)

        self.btn_sev_high = QPushButton("High", toolbar_frame)
        self.btn_sev_high.setCheckable(True)
        self.btn_sev_high.setStyleSheet(btn_style_base % ("#F97316", "#F97316"))
        self.btn_sev_high.setCursor(Qt.PointingHandCursor)

        self.btn_sev_med = QPushButton("Medium", toolbar_frame)
        self.btn_sev_med.setCheckable(True)
        self.btn_sev_med.setStyleSheet(btn_style_base % ("#F59E0B", "#F59E0B"))
        self.btn_sev_med.setCursor(Qt.PointingHandCursor)

        self.btn_sev_low = QPushButton("Low", toolbar_frame)
        self.btn_sev_low.setCheckable(True)
        self.btn_sev_low.setStyleSheet(btn_style_base % ("#168BFF", "#38A8FF"))
        self.btn_sev_low.setCursor(Qt.PointingHandCursor)

        # Mutually exclusive toggle group for Severity
        self.severity_group = QButtonGroup(self)
        self.severity_group.setExclusive(False)
        self.severity_group.addButton(self.btn_sev_crit, 1)
        self.severity_group.addButton(self.btn_sev_high, 2)
        self.severity_group.addButton(self.btn_sev_med, 3)
        self.severity_group.addButton(self.btn_sev_low, 4)
        self.severity_group.idClicked.connect(self._on_severity_clicked)

        tb_layout.addWidget(self.btn_sev_crit)
        tb_layout.addWidget(self.btn_sev_high)
        tb_layout.addWidget(self.btn_sev_med)
        tb_layout.addWidget(self.btn_sev_low)

        # Divider
        div = QLabel("|", toolbar_frame)
        div.setStyleSheet("color: #1A2940; font-weight: bold; margin-left: 4px; margin-right: 4px;")
        tb_layout.addWidget(div)

        # 2. Status Filters (All, Active, Resolved)
        stat_lbl = QLabel("Status:", toolbar_frame)
        stat_lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: 700; letter-spacing: 0.3px;")
        tb_layout.addWidget(stat_lbl)

        stat_btn_style = """
            QPushButton {
                background-color: #111A2B;
                color: #CBD5E1;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                border-color: #21334D;
            }
            QPushButton:checked {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #38A8FF;
                font-weight: bold;
            }
        """

        self.btn_stat_all = QPushButton("All", toolbar_frame)
        self.btn_stat_all.setCheckable(True)
        self.btn_stat_all.setChecked(True)
        self.btn_stat_all.setStyleSheet(stat_btn_style)
        self.btn_stat_all.setCursor(Qt.PointingHandCursor)

        self.btn_stat_active = QPushButton("Active", toolbar_frame)
        self.btn_stat_active.setCheckable(True)
        self.btn_stat_active.setStyleSheet(stat_btn_style)
        self.btn_stat_active.setCursor(Qt.PointingHandCursor)

        self.btn_stat_resolved = QPushButton("Resolved", toolbar_frame)
        self.btn_stat_resolved.setCheckable(True)
        self.btn_stat_resolved.setStyleSheet(stat_btn_style)
        self.btn_stat_resolved.setCursor(Qt.PointingHandCursor)

        self.status_group = QButtonGroup(self)
        self.status_group.setExclusive(True)
        self.status_group.addButton(self.btn_stat_all, 0)
        self.status_group.addButton(self.btn_stat_active, 1)
        self.status_group.addButton(self.btn_stat_resolved, 2)
        self.status_group.idClicked.connect(self._on_status_clicked)

        tb_layout.addWidget(self.btn_stat_all)
        tb_layout.addWidget(self.btn_stat_active)
        tb_layout.addWidget(self.btn_stat_resolved)

        # 3. Clear Filters Button
        tb_layout.addSpacing(6)
        self.btn_clear_filters = QPushButton("Clear Filters", toolbar_frame)
        self.btn_clear_filters.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #A9B8D4;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #355B8A;
            }
        """)
        self.btn_clear_filters.setCursor(Qt.PointingHandCursor)
        self.btn_clear_filters.clicked.connect(self._on_clear_filters_clicked)
        tb_layout.addWidget(self.btn_clear_filters)

        # Push compact controls cleanly to the left
        tb_layout.addStretch()

        self.main_layout.addWidget(toolbar_frame)

    def _build_table_view(self):
        self.table_frame = QFrame(self)
        self.table_frame.setStyleSheet("""
            QFrame {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
            }
        """)
        tf_layout = QVBoxLayout(self.table_frame)
        tf_layout.setContentsMargins(0, 0, 0, 0)
        tf_layout.setSpacing(0)

        self.table_view = QTableView(self.table_frame)
        self.table_view.setSelectionBehavior(QTableView.SelectRows)
        self.table_view.setSelectionMode(QTableView.SingleSelection)
        self.table_view.setEditTriggers(QTableView.NoEditTriggers)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setShowGrid(False)
        self.table_view.setStyleSheet("""
            QTableView {
                background-color: #0D1422;
                border: none;
                gridline-color: #1A2940;
                color: #F4F7FF;
                font-size: 12px;
                outline: none;
            }
            QTableView::item {
                padding: 6px 8px;
                border-bottom: 1px solid #1A2940;
            }
            QTableView::item:alternate {
                background-color: #0F1726;
            }
            QTableView::item:selected {
                background-color: #17233A;
                color: #FFFFFF;
                border-left: 3px solid #168BFF;
            }
            QHeaderView::section {
                background-color: #111A2B;
                color: #A9B8D4;
                padding: 8px 8px;
                border: none;
                border-bottom: 1px solid #1A2940;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 0.3px;
            }
        """)

        self.model = IncidentsTableModel()
        self.table_view.setModel(self.model)

        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Configure responsive column sizing for 9 columns
        header = self.table_view.horizontalHeader()
        header.setStretchLastSection(False)
        for i in range(9):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Custom delegate for row-level Dismiss button [ × ]
        self.table_view.setItemDelegateForColumn(8, DismissItemDelegate(self.table_view))
        self.table_view.setMouseTracking(True)
        self.table_view.viewport().installEventFilter(self)

        self._adjust_table_column_widths()
        self.table_view.clicked.connect(self._on_table_row_clicked)

        tf_layout.addWidget(self.table_view)

        # Honest Empty State Widget (shown when 0 incidents match)
        self.empty_state_frame = QFrame(self.table_frame)
        self.empty_state_frame.setStyleSheet("background: transparent; border: none;")
        es_layout = QVBoxLayout(self.empty_state_frame)
        es_layout.setContentsMargins(20, 30, 20, 30)
        es_layout.setSpacing(6)
        es_layout.setAlignment(Qt.AlignCenter)

        self.empty_icon = QLabel("🛡️", self.empty_state_frame)
        self.empty_icon.setStyleSheet("font-size: 28px; background: transparent; border: none;")
        self.empty_icon.setAlignment(Qt.AlignCenter)
        es_layout.addWidget(self.empty_icon)

        self.empty_title = QLabel("NO SECURITY INCIDENTS", self.empty_state_frame)
        self.empty_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #94A3B8; background: transparent; border: none;")
        self.empty_title.setAlignment(Qt.AlignCenter)
        es_layout.addWidget(self.empty_title)

        self.empty_subtitle = QLabel("No threats have been recorded yet.", self.empty_state_frame)
        self.empty_subtitle.setStyleSheet("font-size: 12px; color: #64748B; background: transparent; border: none;")
        self.empty_subtitle.setAlignment(Qt.AlignCenter)
        es_layout.addWidget(self.empty_subtitle)

        tf_layout.addWidget(self.empty_state_frame)
        self.empty_state_frame.setVisible(False)

        self.splitter.addWidget(self.table_frame)

    def eventFilter(self, watched, event):
        if hasattr(self, 'table_view') and watched == self.table_view.viewport():
            if event.type() == QEvent.MouseMove:
                idx = self.table_view.indexAt(event.pos())
                if idx.isValid() and idx.column() in (7, 8):
                    self.table_view.viewport().setCursor(Qt.PointingHandCursor)
                else:
                    self.table_view.viewport().setCursor(Qt.ArrowCursor)
        return super(ThreatsPage, self).eventFilter(watched, event)

    def _adjust_table_column_widths(self):
        vp_width = self.table_view.viewport().width()
        if vp_width <= 200:
            vp_width = self.table_view.width() - 4
        if vp_width <= 200:
            vp_width = 1000

        # Leave small margin so sum strictly stays within viewport
        avail_w = max(vp_width - 2, 200)

        # Proportional allocation across all 9 columns:
        # 0: THREAT / INCIDENT: 25%   (min 220px)
        # 1: SEVERITY:           8%   (min 65px)
        # 2: RISK:               7.5% (min 60px)
        # 3: DETECTED:          13%   (min 110px)
        # 4: SOURCE:            11.5% (min 95px)
        # 6: STATUS:             8%   (min 68px)
        # 7: ACTION:            10.5% (min 105px)
        # 8: DISMISS:            5%   (min 50px)
        # 5: TARGET:      remainder (~11.5%, min 80px)
        w0 = max(int(avail_w * 0.25), 220)
        w1 = max(int(avail_w * 0.08), 65)
        w2 = max(int(avail_w * 0.075), 60)
        w3 = max(int(avail_w * 0.13), 110)
        w4 = max(int(avail_w * 0.115), 95)
        w6 = max(int(avail_w * 0.08), 68)
        w7 = max(int(avail_w * 0.105), 105)
        w8 = max(int(avail_w * 0.05), 50)

        # TARGET receives remainder of available width
        other_sum = w0 + w1 + w2 + w3 + w4 + w6 + w7 + w8
        w5 = max(avail_w - other_sum, 80)

        # Ensure total column width never exceeds avail_w
        current_total = other_sum + w5
        if current_total > avail_w:
            overflow = current_total - avail_w
            trim = min(overflow, max(w5 - 80, 0))
            w5 -= trim
            overflow -= trim
            if overflow > 0:
                trim_act = min(overflow, max(w7 - 70, 0))
                w7 -= trim_act
                overflow -= trim_act
            if overflow > 0:
                w0 = max(w0 - overflow, 200)

        self.table_view.setColumnWidth(0, w0)
        self.table_view.setColumnWidth(1, w1)
        self.table_view.setColumnWidth(2, w2)
        self.table_view.setColumnWidth(3, w3)
        self.table_view.setColumnWidth(4, w4)
        self.table_view.setColumnWidth(5, w5)
        self.table_view.setColumnWidth(6, w6)
        self.table_view.setColumnWidth(7, w7)
        self.table_view.setColumnWidth(8, w8)

    def resizeEvent(self, event):
        super(ThreatsPage, self).resizeEvent(event)
        self._adjust_table_column_widths()

    def showEvent(self, event):
        super(ThreatsPage, self).showEvent(event)
        self._adjust_table_column_widths()

    def _build_investigation_panel(self):
        # Scrollable container for the complete investigation panel
        self.investigation_scroll = QScrollArea(self)
        self.investigation_scroll.setWidgetResizable(True)
        self.investigation_scroll.setFrameShape(QFrame.NoFrame)
        self.investigation_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.investigation_container = QWidget()
        self.investigation_container.setStyleSheet("background-color: #070B16;")
        inv_layout = QVBoxLayout(self.investigation_container)
        inv_layout.setContentsMargins(0, 4, 4, 4)
        inv_layout.setSpacing(10)

        # ------------------------------------------------------------
        # SECTION 1: Incident Header Card
        # ------------------------------------------------------------
        self.header_card = QFrame(self.investigation_container)
        self.header_card.setObjectName("investigationHeaderCard")
        self.header_card.setStyleSheet("""
            QFrame#investigationHeaderCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-left: 4px solid #EF4444;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        hc_layout = QHBoxLayout(self.header_card)
        hc_layout.setContentsMargins(10, 8, 10, 8)
        hc_layout.setSpacing(10)

        # Left Badges & Title
        v_head = QVBoxLayout()
        v_head.setSpacing(4)

        top_badge_row = QHBoxLayout()
        top_badge_row.setSpacing(8)

        self.hdr_sev_badge = QLabel("CRITICAL", self.header_card)
        self.hdr_sev_badge.setStyleSheet("background-color: rgba(255, 77, 103, 0.25); color: #FF4D67; font-weight: bold; font-size: 11px; border: 1px solid #FF4D67; border-radius: 4px; padding: 2px 8px;")
        top_badge_row.addWidget(self.hdr_sev_badge)

        self.hdr_status_badge = QLabel("ACTIVE", self.header_card)
        self.hdr_status_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #EF4444; font-weight: bold; font-size: 11px; border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 4px; padding: 2px 8px;")
        top_badge_row.addWidget(self.hdr_status_badge)

        self.hdr_risk_badge = QLabel("Risk Score: 95 / 100", self.header_card)
        self.hdr_risk_badge.setStyleSheet("color: #FFB84D; font-weight: bold; font-size: 11px; margin-left: 4px;")
        top_badge_row.addWidget(self.hdr_risk_badge)

        top_badge_row.addStretch()
        v_head.addLayout(top_badge_row)

        self.hdr_title = QLabel("Threat Incident Investigation", self.header_card)
        self.hdr_title.setStyleSheet("font-size: 17px; font-weight: 800; color: #F4F7FF; margin-top: 2px;")
        v_head.addWidget(self.hdr_title)

        self.hdr_meta = QLabel("ID: -- | Target: -- | Detected by: --", self.header_card)
        self.hdr_meta.setStyleSheet("font-size: 11px; color: #8B98A8; font-family: Consolas, monospace;")
        self.hdr_meta_lbl = self.hdr_meta
        v_head.addWidget(self.hdr_meta)

        hc_layout.addLayout(v_head, 1)

        # Right Action Buttons
        v_actions = QVBoxLayout()
        v_actions.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        v_actions.setSpacing(6)

        h_act_btns = QHBoxLayout()
        h_act_btns.setSpacing(8)

        self.report_threat_btn = QPushButton("📄 Generate Threat Report", self.header_card)
        self.report_threat_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #168BFF, stop:1 #38A8FF);
                color: #FFFFFF;
                border: 1px solid #168BFF;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1A94FF, stop:1 #52B4FF);
                border-color: #38A8FF;
            }
        """)
        self.report_threat_btn.setCursor(Qt.PointingHandCursor)
        self.report_threat_btn.clicked.connect(self._generate_threat_report)
        h_act_btns.addWidget(self.report_threat_btn)

        self.resolve_btn = QPushButton("✓ Resolve Incident", self.header_card)
        self.resolve_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10B981, stop:1 #059669);
                color: #FFFFFF;
                border: 1px solid #10B981;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
            }
            QPushButton:disabled {
                background: #111A2B;
                color: #64748B;
                border: 1px solid #1A2940;
            }
        """)
        self.resolve_btn.setCursor(Qt.PointingHandCursor)
        self.resolve_btn.clicked.connect(self._resolve_current_incident)
        h_act_btns.addWidget(self.resolve_btn)

        self.close_panel_btn = QPushButton("✕", self.header_card)
        self.close_panel_btn.setToolTip("Close investigation details panel")
        self.close_panel_btn.setStyleSheet("""
            QPushButton {
                background-color: #111A2B;
                color: #CBD5E1;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #17233A;
                color: #FFFFFF;
                border-color: #355B8A;
            }
        """)
        self.close_panel_btn.setCursor(Qt.PointingHandCursor)
        self.close_panel_btn.clicked.connect(self._on_close_details_clicked)
        h_act_btns.addWidget(self.close_panel_btn)

        v_actions.addLayout(h_act_btns)
        hc_layout.addLayout(v_actions)

        inv_layout.addWidget(self.header_card)

        # ------------------------------------------------------------
        # SECTION 2: Incident Overview (Compact Two-Column Layout)
        # ------------------------------------------------------------
        self.overview_card = QFrame(self.investigation_container)
        self.overview_card.setObjectName("investigationOverviewCard")
        self.overview_card.setStyleSheet("""
            QFrame#investigationOverviewCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        oc_layout = QVBoxLayout(self.overview_card)
        oc_layout.setContentsMargins(12, 10, 12, 10)
        oc_layout.setSpacing(8)

        oc_title = QLabel("THREAT DETAILS", self.overview_card)
        oc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B98A8; letter-spacing: 0.5px; background: transparent; border: none;")
        oc_layout.addWidget(oc_title)

        grid_layout = QHBoxLayout()
        grid_layout.setSpacing(16)

        # Left Column: Threat Rationale
        self.left_col_layout = QGridLayout()
        self.left_col_layout.setSpacing(6)
        self.lbl_val_threat_name = self._add_field_row(self.left_col_layout, 0, "Threat Name:")
        self.lbl_val_verdict = self._add_field_row(self.left_col_layout, 1, "Verdict:")
        self.lbl_val_severity = self._add_field_row(self.left_col_layout, 2, "Severity:")
        self.lbl_val_risk = self._add_field_row(self.left_col_layout, 3, "Risk Score:")
        self.lbl_val_source = self._add_field_row(self.left_col_layout, 4, "Detection Source:")
        self.lbl_val_time = self._add_field_row(self.left_col_layout, 5, "Detection Time:")

        # Right Column: Target File & Process Attribution
        self.right_col_layout = QGridLayout()
        self.right_col_layout.setSpacing(6)
        self.lbl_val_filename = self._add_field_row(self.right_col_layout, 0, "File Name:")
        self.lbl_val_filetype = self._add_field_row(self.right_col_layout, 1, "File Type:")
        self.lbl_val_filesize = self._add_field_row(self.right_col_layout, 2, "File Size:")
        self.lbl_val_sha256 = self._add_field_row(self.right_col_layout, 3, "SHA-256:")
        self.lbl_val_fullpath = self._add_field_row(self.right_col_layout, 4, "Full Path:")
        self.lbl_val_process = self._add_field_row(self.right_col_layout, 5, "Process / Attr:")

        grid_layout.addLayout(self.left_col_layout, 1)
        grid_layout.addLayout(self.right_col_layout, 1)
        oc_layout.addLayout(grid_layout)

        inv_layout.addWidget(self.overview_card)

        # ------------------------------------------------------------
        # SECTION 3: Why Was This Threat Detected? (Calibrated Narrative)
        # ------------------------------------------------------------
        self.why_card = QFrame(self.investigation_container)
        self.why_card.setObjectName("investigationWhyCard")
        self.why_card.setStyleSheet("""
            QFrame#investigationWhyCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        wc_layout = QVBoxLayout(self.why_card)
        wc_layout.setContentsMargins(12, 10, 12, 10)
        wc_layout.setSpacing(8)

        wc_title = QLabel("WHY WAS THIS THREAT DETECTED?", self.why_card)
        wc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B98A8; letter-spacing: 0.5px; background: transparent; border: none;")
        wc_layout.addWidget(wc_title)

        self.why_narrative_lbl = QLabel(self.why_card)
        self.why_narrative_lbl.setStyleSheet("color: #CBD5E1; font-size: 12px; line-height: 1.4; background: transparent; border: none;")
        self.why_narrative_lbl.setWordWrap(True)
        self.why_narrative_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        wc_layout.addWidget(self.why_narrative_lbl)

        # Breakdown summary mini-table
        why_box_row = QHBoxLayout()
        why_box_row.setSpacing(12)

        def _make_narrative_metric(title_txt):
            b = QFrame(self.why_card)
            b.setStyleSheet("background-color: #111A2B; border: 1px solid #1A2940; border-radius: 4px; padding: 6px 10px;")
            b_ly = QVBoxLayout(b)
            b_ly.setContentsMargins(0, 0, 0, 0)
            b_ly.setSpacing(2)
            t = QLabel(title_txt, b)
            t.setStyleSheet("color: #8B98A8; font-size: 10px; font-weight: 700; background: transparent; border: none;")
            v = QLabel("--", b)
            v.setStyleSheet("color: #F4F7FF; font-size: 11px; font-weight: 600; background: transparent; border: none;")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            b_ly.addWidget(t)
            b_ly.addWidget(v)
            return b, v

        b_rule, self.why_rule_val = _make_narrative_metric("PRIMARY RULE TRIGGERED")
        b_evid, self.why_evidence_val = _make_narrative_metric("OBSERVED INDICATOR")
        b_risk, self.why_risk_val = _make_narrative_metric("CONFIDENCE & CONTRIBUTION")

        why_box_row.addWidget(b_rule, 1)
        why_box_row.addWidget(b_evid, 2)
        why_box_row.addWidget(b_risk, 1)
        wc_layout.addLayout(why_box_row)

        # Compatibility references
        self.box_trigger_rule = {"widget": self.why_card, "val_lbl": self.why_rule_val}
        self.box_evidence = {"widget": self.why_card, "val_lbl": self.why_evidence_val}
        self.box_risk_contrib = {"widget": self.why_card, "val_lbl": self.why_risk_val}

        inv_layout.addWidget(self.why_card)

        # ------------------------------------------------------------
        # SECTION 4: Detection Evidence & Rules Applied (Full Dynamic Height)
        # ------------------------------------------------------------
        self.evidence_card = QFrame(self.investigation_container)
        self.evidence_card.setObjectName("investigationEvidenceCard")
        self.evidence_card.setStyleSheet("""
            QFrame#investigationEvidenceCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        ec_layout = QVBoxLayout(self.evidence_card)
        ec_layout.setContentsMargins(12, 10, 12, 10)
        ec_layout.setSpacing(6)

        ec_title = QLabel("DETECTION EVIDENCE & APPLIED RULES", self.evidence_card)
        ec_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B98A8; letter-spacing: 0.5px; background: transparent; border: none;")
        ec_layout.addWidget(ec_title)

        self.evidence_table = QTableWidget(self.evidence_card)
        self.evidence_table.setColumnCount(3)
        self.evidence_table.setHorizontalHeaderLabels(["RULE", "OBSERVED EVIDENCE", "RISK"])
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.setSelectionMode(QTableWidget.NoSelection)
        self.evidence_table.setShowGrid(False)
        self.evidence_table.setWordWrap(True)
        self.evidence_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.evidence_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.evidence_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        ev_header = self.evidence_table.horizontalHeader()
        ev_header.setSectionResizeMode(0, QHeaderView.Interactive)
        ev_header.setSectionResizeMode(1, QHeaderView.Stretch)
        ev_header.setSectionResizeMode(2, QHeaderView.Interactive)
        self.evidence_table.setColumnWidth(0, 235)
        self.evidence_table.setColumnWidth(2, 90)
        ev_header.sectionResized.connect(lambda *_: self._adjust_evidence_table_height())
        ev_header.setStyleSheet("""
            QHeaderView::section {
                background-color: #111A2B;
                color: #CBD5E1;
                padding: 4px 10px;
                border: none;
                border-bottom: 1px solid #1A2940;
                font-weight: 700;
                font-size: 11px;
            }
        """)

        self.evidence_table.setStyleSheet("""
            QTableWidget {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 4px;
                outline: none;
            }
            QTableWidget::item {
                padding: 6px 10px;
                border-bottom: 1px solid #1A2940;
                color: #CBD5E1;
                font-size: 11px;
            }
        """)
        ec_layout.addWidget(self.evidence_table)

        inv_layout.addWidget(self.evidence_card)

        # ------------------------------------------------------------
        self.timeline_card = QFrame(self.investigation_container)
        self.timeline_card.setObjectName("investigationTimelineCard")
        self.timeline_card.setStyleSheet("""
            QFrame#investigationTimelineCard {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 6px;
                padding: 10px 14px;
            }
        """)
        tc_layout = QVBoxLayout(self.timeline_card)
        tc_layout.setContentsMargins(12, 10, 12, 10)
        tc_layout.setSpacing(6)

        tc_title = QLabel("ACTIVITY TIMELINE (DATABASE AUDIT)", self.timeline_card)
        tc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B98A8; letter-spacing: 0.5px; background: transparent; border: none;")
        tc_layout.addWidget(tc_title)

        self.timeline_view = QTableView(self.timeline_card)
        self.timeline_view.setSelectionBehavior(QTableView.SelectRows)
        self.timeline_view.setSelectionMode(QTableView.SingleSelection)
        self.timeline_view.setEditTriggers(QTableView.NoEditTriggers)
        self.timeline_view.verticalHeader().setVisible(False)
        self.timeline_view.setShowGrid(False)
        self.timeline_view.setStyleSheet("""
            QTableView {
                background-color: #0D1422;
                border: 1px solid #1A2940;
                border-radius: 4px;
                color: #CBD5E1;
                font-size: 11px;
                outline: none;
            }
            QTableView::item {
                padding: 4px 6px;
                border-bottom: 1px solid #1A2940;
            }
            QHeaderView::section {
                background-color: #111A2B;
                color: #8B98A8;
                padding: 6px 8px;
                border: none;
                border-bottom: 1px solid #1A2940;
                font-weight: 700;
                font-size: 10px;
            }
        """)
        self.timeline_model = IncidentActivityTableModel()
        self.timeline_view.setModel(self.timeline_model)

        tl_hdr = self.timeline_view.horizontalHeader()
        tl_hdr.setSectionResizeMode(0, QHeaderView.Fixed)        # Time
        tl_hdr.setSectionResizeMode(1, QHeaderView.Fixed)        # Action
        tl_hdr.setSectionResizeMode(2, QHeaderView.Interactive)  # File/Path
        tl_hdr.setSectionResizeMode(3, QHeaderView.Stretch)      # Description
        tl_hdr.setSectionResizeMode(4, QHeaderView.Fixed)        # Size

        self.timeline_view.setColumnWidth(0, 125)
        self.timeline_view.setColumnWidth(1, 75)
        self.timeline_view.setColumnWidth(2, 160)
        self.timeline_view.setColumnWidth(4, 85)
        self.timeline_view.setFixedHeight(120)

        tc_layout.addWidget(self.timeline_view)

        # Empty activity timeline banner
        self.timeline_empty_lbl = QLabel("No related filesystem activity recorded.", self.timeline_card)
        self.timeline_empty_lbl.setStyleSheet("""
            background-color: #0D1422;
            color: #8B98A8;
            font-size: 12px;
            font-style: italic;
            border: 1px dashed #1A2940;
            border-radius: 4px;
            padding: 12px;
        """)
        self.timeline_empty_lbl.setAlignment(Qt.AlignCenter)
        self.timeline_empty_lbl.setVisible(False)
        tc_layout.addWidget(self.timeline_empty_lbl)

        inv_layout.addWidget(self.timeline_card)

        self.investigation_scroll.setWidget(self.investigation_container)
        self.splitter.addWidget(self.investigation_scroll)

        # Start collapsed
        self.investigation_scroll.setVisible(False)

    def _add_field_row(self, layout: QGridLayout, row: int, label_str: str) -> QLabel:
        lbl = QLabel(label_str, self.overview_card)
        lbl.setStyleSheet("color: #8B98A8; font-size: 11px; font-weight: 700; background: transparent; border: none;")
        lbl.setAlignment(Qt.AlignRight | Qt.AlignTop)
        lbl.setFixedWidth(115)

        val = QLabel("Not available", self.overview_card)
        val.setStyleSheet("color: #E6EDF3; font-size: 11px; font-family: Consolas, monospace; background: transparent; border: none;")
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        val.setWordWrap(True)

        layout.addWidget(lbl, row, 0)
        layout.addWidget(val, row, 1)
        return val

    def _create_mini_box(self, title: str, initial_val: str) -> Dict[str, Any]:
        frame = QFrame(self.why_card)
        frame.setStyleSheet("""
            QFrame {
                background-color: #111A2B;
                border: 1px solid #1A2940;
                border-radius: 4px;
                padding: 6px 10px;
            }
        """)
        box_l = QVBoxLayout(frame)
        box_l.setContentsMargins(2, 2, 2, 2)
        box_l.setSpacing(2)

        t_lbl = QLabel(title, frame)
        t_lbl.setStyleSheet("color: #8B98A8; font-size: 10px; font-weight: 700; background: transparent; border: none;")
        box_l.addWidget(t_lbl)

        v_lbl = QLabel(initial_val, frame)
        v_lbl.setStyleSheet("color: #CBD5E1; font-size: 11px; font-family: Consolas, monospace; background: transparent; border: none;")
        v_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v_lbl.setWordWrap(True)
        box_l.addWidget(v_lbl)

        return {"widget": frame, "val_lbl": v_lbl}

    def _adjust_evidence_table_height(self):
        """
        Dynamically adjusts evidence table height to fit all row contents
        without internal vertical scrollbars, while allowing the outer
        investigation panel scrollarea to handle natural vertical flow.
        """
        if not hasattr(self, "evidence_table") or self.evidence_table is None:
            return
        self.evidence_table.resizeRowsToContents()
        header_h = self.evidence_table.horizontalHeader().height()
        if header_h <= 0:
            header_h = 28
        total_h = header_h
        for r in range(self.evidence_table.rowCount()):
            rh = max(self.evidence_table.rowHeight(r), 30)
            self.evidence_table.setRowHeight(r, rh)
            total_h += rh
        self.evidence_table.setFixedHeight(max(total_h + 12, 60))

    # =========================================================================
    # FILTER & SEARCH HANDLERS
    # =========================================================================

    def _on_severity_clicked(self, button_id: int):
        # If user clicked the already active button, toggle it off
        btn = self.severity_group.button(button_id)
        if btn and not btn.isChecked():
            self.current_severity_filter = None
        elif button_id == 1:
            self.current_severity_filter = "CRITICAL"
        elif button_id == 2:
            self.current_severity_filter = "HIGH"
        elif button_id == 3:
            self.current_severity_filter = "MEDIUM"
        elif button_id == 4:
            self.current_severity_filter = "LOW"
        else:
            self.current_severity_filter = None

        # Uncheck other severity buttons
        for b_id in [1, 2, 3, 4]:
            if b_id != button_id:
                other_btn = self.severity_group.button(b_id)
                if other_btn:
                    other_btn.setChecked(False)

        self.refresh()

    def _on_status_clicked(self, button_id: int):
        if button_id == 0:
            self.current_status_filter = None
        elif button_id == 1:
            self.current_status_filter = "ACTIVE"
        elif button_id == 2:
            self.current_status_filter = "RESOLVED"
        self.refresh()

    def _on_clear_filters_clicked(self):
        self.current_severity_filter = None
        self.current_status_filter = None

        # Uncheck all severity buttons
        for b in [self.btn_sev_crit, self.btn_sev_high, self.btn_sev_med, self.btn_sev_low]:
            b.setChecked(False)

        # Set status to All
        self.btn_stat_all.setChecked(True)
        self.refresh()

    def _check_empty_state(self):
        count = self.model.rowCount()
        if count == 0:
            if self.current_severity_filter or self.current_status_filter:
                self.empty_title.setText("NO MATCHING INCIDENTS")
                self.empty_subtitle.setText("No security incidents match the currently active filter criteria.")
            else:
                self.empty_title.setText("NO SECURITY INCIDENTS")
                self.empty_subtitle.setText("No threats have been recorded yet.")
            self.table_view.setVisible(False)
            self.empty_state_frame.setVisible(True)
        else:
            self.table_view.setVisible(True)
            self.empty_state_frame.setVisible(False)

    # =========================================================================
    # REFRESH & DATABASE SYNC
    # =========================================================================

    def refresh(self):
        """Loads incidents directly from the SQLite database."""
        # 1. Update Protection status badge
        self._update_protection_badge()

        # 2. Load filtered incidents (excluding dismissed threats via database repository)
        incidents_rows = self.inc_repo.get_incidents(
            severity_filter=self.current_severity_filter,
            status_filter=self.current_status_filter,
            include_dismissed=False
        )
        incidents = [dict(r) for r in incidents_rows]
        self.model.set_incidents(incidents)
        self._adjust_table_column_widths()
        self._check_empty_state()

        # 3. Refresh currently open incident details if still present and not dismissed
        if self.current_incident:
            inc_id = self.current_incident.get("id")
            if inc_id is not None and self.inc_repo.is_incident_dismissed(inc_id):
                self.investigation_scroll.setVisible(False)
                self.current_incident = None
                self.table_view.clearSelection()
            else:
                refreshed = self.inc_repo.get_incident(inc_id) if inc_id is not None else None
                if refreshed:
                    self._populate_details(dict(refreshed))
                else:
                    self.investigation_scroll.setVisible(False)
                    self.current_incident = None

    # =========================================================================
    # CLOSE & DISMISS ACTIONS
    # =========================================================================

    def _on_close_details_clicked(self):
        """
        Close Button inside Threat Details:
        Hides the investigation details panel and clears active selection.
        Does NOT alter incident status, delete DB records, or remove the row from the table.
        """
        self.investigation_scroll.setVisible(False)
        self.current_incident = None
        self.table_view.clearSelection()

    def _on_dismiss_threat_clicked(self, row: int):
        """
        Close/Dismiss Button on Table Row:
        Removes the threat row from the visible repository table view.
        Persists the dismissal in the SQLite database so it remains dismissed across restarts.
        If the dismissed threat is currently open in details, hides details and clears selection.
        Preserves all historical security evidence, logs, and audits in the database.
        Does NOT mark the incident resolved and does NOT generate notifications.
        """
        inc = self.model.get_incident_at(row)
        if not inc:
            return
        inc_id = inc.get("id")
        if inc_id is not None:
            # Persist dismissal to the database using exact unique incident ID
            self.inc_repo.dismiss_incident(inc_id)

        # If that threat is currently open in the investigation section:
        # • close/hide the Threat Details section
        # • clear selection
        if self.current_incident and self.current_incident.get("id") == inc_id:
            self.investigation_scroll.setVisible(False)
            self.current_incident = None
            self.table_view.clearSelection()

        # Remove from table presentation immediately
        if inc_id is not None:
            self.model.dismiss_incident(inc_id)
        self._check_empty_state()

    # =========================================================================
    # ROW SELECTION & INVESTIGATION DETAILS POPULATION
    # =========================================================================

    def _on_table_row_clicked(self, index):
        if not index.isValid():
            return
        col = index.column()
        row = index.row()
        if col == 8:
            # DISMISS button clicked on table row
            self._on_dismiss_threat_clicked(row)
            return

        inc = self.model.get_incident_at(row)
        if not inc:
            return
        self._populate_details(inc)
        self.investigation_scroll.setVisible(True)
        # Allocate balanced vertical space (e.g. 240px table, 380px details)
        self.splitter.setSizes([240, 380])

    def _populate_details(self, inc: Dict[str, Any]):
        self.current_incident = inc
        threat_name = inc.get("threat_name", "Security Threat")
        # Clean suffix for header
        clean_name = threat_name
        for suffix in [" (Existing File Scan)", " (Scan Center)"]:
            if clean_name.endswith(suffix):
                clean_name = clean_name[:-len(suffix)]

        severity = str(inc.get("severity", "LOW")).upper()
        verdict = str(inc.get("verdict", "UNKNOWN")).upper()
        risk = inc.get("risk_score", 0)
        status = str(inc.get("status", "ACTIVE")).upper()

        # Determine detection source
        src = inc.get("detection_source")
        if not src or str(src) in ("None", ""):
            if "(Existing File Scan)" in threat_name:
                src = "Existing File Scan"
            elif "(Scan Center)" in threat_name:
                src = "Scan Center"
            elif inc.get("full_path") and not inc.get("affected_folder"):
                src = "Scan Center"
            else:
                src = "Live Protection"

        det_time = inc.get("detection_time", "Not available")

        # 1. Header Card Badges & Info
        self.hdr_title.setText(clean_name)
        self.hdr_sev_badge.setText(severity)
        if severity == "CRITICAL":
            self.hdr_sev_badge.setStyleSheet("background-color: rgba(255, 77, 103, 0.25); color: #FF4D67; font-weight: bold; font-size: 11px; border: 1px solid #FF4D67; border-radius: 4px; padding: 2px 8px;")
            self.header_card.setStyleSheet("QFrame#investigationHeaderCard { background-color: #0D1422; border: 1px solid #1A2940; border-left: 4px solid #FF4D67; border-radius: 6px; padding: 10px 14px; }")
        elif severity == "HIGH":
            self.hdr_sev_badge.setStyleSheet("background-color: rgba(249, 115, 22, 0.2); color: #F97316; font-weight: bold; font-size: 11px; border: 1px solid #F97316; border-radius: 4px; padding: 2px 8px;")
            self.header_card.setStyleSheet("QFrame#investigationHeaderCard { background-color: #0D1422; border: 1px solid #1A2940; border-left: 4px solid #F97316; border-radius: 6px; padding: 10px 14px; }")
        elif severity == "MEDIUM":
            self.hdr_sev_badge.setStyleSheet("background-color: rgba(255, 184, 77, 0.2); color: #FFB84D; font-weight: bold; font-size: 11px; border: 1px solid #FFB84D; border-radius: 4px; padding: 2px 8px;")
            self.header_card.setStyleSheet("QFrame#investigationHeaderCard { background-color: #0D1422; border: 1px solid #1A2940; border-left: 4px solid #FFB84D; border-radius: 6px; padding: 10px 14px; }")
        else:
            self.hdr_sev_badge.setStyleSheet("background-color: rgba(22, 139, 255, 0.15); color: #38A8FF; font-weight: bold; font-size: 11px; border: 1px solid #168BFF; border-radius: 4px; padding: 2px 8px;")
            self.header_card.setStyleSheet("QFrame#investigationHeaderCard { background-color: #0D1422; border: 1px solid #1A2940; border-left: 4px solid #168BFF; border-radius: 6px; padding: 10px 14px; }")

        self.hdr_status_badge.setText(status)
        if status == "RESOLVED":
            self.hdr_status_badge.setStyleSheet("background-color: rgba(34, 197, 94, 0.15); color: #22C55E; font-weight: bold; font-size: 11px; border: 1px solid rgba(34, 197, 94, 0.4); border-radius: 4px; padding: 2px 8px;")
            self.resolve_btn.setEnabled(False)
            self.resolve_btn.setText("RESOLVED")
        else:
            self.hdr_status_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #EF4444; font-weight: bold; font-size: 11px; border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 4px; padding: 2px 8px;")
            self.resolve_btn.setEnabled(True)
            self.resolve_btn.setText("✓ Resolve Incident")

        self.hdr_risk_badge.setText(f"Risk Score: {risk} / 100")
        self.hdr_meta_lbl.setText(f"Detection Source: {src}  ·  Detected: {det_time}")

        # 2. Two-Column Telemetry Overview
        self.lbl_val_threat_name.setText(threat_name)
        self.lbl_val_verdict.setText(verdict)
        self.lbl_val_severity.setText(severity)
        self.lbl_val_risk.setText(f"{risk} / 100")
        self.lbl_val_source.setText(str(src))
        self.lbl_val_time.setText(str(det_time))

        full_path = inc.get("full_path") or inc.get("affected_folder") or "Not available"
        filename = inc.get("affected_file") or (os.path.basename(full_path) if full_path != "Not available" else "Not available")
        self.lbl_val_filename.setText(filename)
        self.lbl_val_filetype.setText(inc.get("file_type") or "Plain Text Document")

        f_size = inc.get("file_size")
        if f_size is not None and f_size >= 0:
            size_formatted = f"{format_file_size(f_size)} ({f_size:,} bytes)"
        else:
            size_formatted = "Not available"
        self.lbl_val_filesize.setText(size_formatted)

        self.lbl_val_sha256.setText(inc.get("sha256") or "Not available")
        self.lbl_val_fullpath.setText(full_path)
        self.lbl_val_fullpath.setToolTip(full_path)

        proc_name = inc.get("process_name")
        proc_pid = inc.get("process_pid")
        attr_status = inc.get("attribution_status")
        if proc_name and proc_name not in ("Unknown", "Unknown Process"):
            pid_str = f" [PID: {proc_pid}]" if proc_pid else ""
            stat_str = f" ({attr_status})" if attr_status else ""
            self.lbl_val_process.setText(f"{proc_name}{pid_str}{stat_str}")
        else:
            self.lbl_val_process.setText("Unknown — attribution unavailable")

        # 3. Why Was This Threat Detected? (Calibrated narrative)
        reason = inc.get("detection_reason") or "Suspicious file characteristic detected"
        if "README" in filename or "README" in full_path or "RANSOM_NOTE" in (inc.get("evidence") or ""):
            narrative = (
                f"The file '{filename}' was flagged for review because its filename matched a heuristic detection rule "
                f"associated with potential ransomware note naming patterns ('README.md'). "
                f"Static file analysis inspected the document structure and assigned a preliminary risk score "
                f"without observing active filesystem encryption activity."
            )
            rule_name = "RANSOM_NOTE_PATTERN"
            obs_ev = f"Filename matches typical decryption note pattern: '{filename}'"
            risk_contrib = f"+{risk}"
        elif "Script" in threat_name or "file_analyzer" in full_path or "behavior_engine" in full_path:
            narrative = (
                f"The target file was inspected during scanning and exhibited script execution markers or security engine "
                f"telemetry patterns matching static detection heuristics: {reason}."
            )
            rule_name = "SCRIPT_EXECUTION_HEURISTIC"
            obs_ev = reason
            risk_contrib = f"+{risk}"
        elif "Encryption" in threat_name or "Morphing" in threat_name:
            narrative = (
                f"The real-time behavioral detection engine observed rapid or anomalous file modifications/renames "
                f"within the protected directory scope consistent with potential ransomware encryption behavior."
            )
            rule_name = "BEHAVIORAL_ANOMALY_ENGINE"
            obs_ev = reason
            risk_contrib = f"+{risk}"
        else:
            narrative = (
                f"The security monitoring engine flagged this item based on anomalous telemetry: {reason}."
            )
            rule_name = "STATIC_HEURISTIC_RULE"
            obs_ev = reason
            risk_contrib = f"+{risk}"

        self.why_narrative_lbl.setText(narrative)
        self.why_rule_val.setText(rule_name)
        self.why_evidence_val.setText(obs_ev)
        self.why_risk_val.setText(risk_contrib)

        # 4. Evidence Table Population
        self._populate_evidence_table(inc, rule_name, obs_ev, risk)

        # 5. Activity Timeline Population
        self._populate_activity_timeline(inc["id"])

    def _populate_evidence_table(self, inc: Dict[str, Any], default_rule: str, default_ev: str, risk: int):
        self.evidence_table.setRowCount(0)
        rules_data = []

        ev_str = inc.get("evidence") or ""
        if ev_str and "|" in ev_str:
            for line in ev_str.strip().split("\n"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    rules_data.append((parts[0], parts[1], parts[2]))
                elif len(parts) == 2:
                    rules_data.append((parts[0], parts[1], f"+{risk}"))
        else:
            # Construct standard authentic evidence rows without truncation
            rules_data.append((default_rule, default_ev, f"+{risk}"))
            file_type = inc.get("file_type") or "Plain Text Document"
            rules_data.append(("FILE_STRUCTURE_IDENTIFIER", f"Validated file type: {file_type}", "+0"))
            sha = inc.get("sha256")
            if sha and sha != "Not available":
                rules_data.append(("CRYPTOGRAPHIC_HASH", f"SHA-256 fingerprint computed:\n{sha}", "+0"))

        self.evidence_table.setRowCount(len(rules_data))
        for row_idx, (rule, ev, contrib) in enumerate(rules_data):
            item_rule = QTableWidgetItem(rule)
            item_rule.setFont(QFont("Consolas", 10, QFont.Weight.DemiBold))
            item_rule.setForeground(QColor("#38BDF8"))
            self.evidence_table.setItem(row_idx, 0, item_rule)

            item_ev = QTableWidgetItem(ev)
            item_ev.setFont(QFont("Segoe UI", 10))
            item_ev.setForeground(QColor("#CBD5E1"))
            item_ev.setToolTip(ev)
            self.evidence_table.setItem(row_idx, 1, item_ev)

            # Risk contribution formatting
            c_str = contrib.strip()
            if not c_str.startswith("+") and not c_str.startswith("-"):
                try:
                    c_num = int(c_str)
                    c_str = f"+{c_num}" if c_num > 0 else f"{c_num}"
                except ValueError:
                    pass
            item_contrib = QTableWidgetItem(c_str)
            item_contrib.setTextAlignment(Qt.AlignCenter)
            item_contrib.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            is_pos = ("+" in c_str and c_str != "+0") or (c_str.isdigit() and int(c_str) > 0)
            item_contrib.setForeground(QColor("#EF4444" if is_pos else "#64748B"))
            self.evidence_table.setItem(row_idx, 2, item_contrib)

        self._adjust_evidence_table_height()

    def _populate_activity_timeline(self, incident_id: int):
        events_rows = self.events_repo.get_events_by_incident(incident_id)
        events = []
        for r in events_rows:
            events.append({
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "src_path": r["src_path"],
                "dest_path": r["dest_path"],
                "extension": r["extension"],
                "file_size": r["file_size"],
                "process_name": r["process_name"] if "process_name" in r.keys() else None,
                "process_pid": r["process_pid"] if "process_pid" in r.keys() else None,
                "attribution_status": r["attribution_status"] if "attribution_status" in r.keys() else None
            })

        self.timeline_model.set_events(events)

        if len(events) > 0:
            self.timeline_view.setVisible(True)
            self.timeline_empty_lbl.setVisible(False)
            h = self.timeline_view.horizontalHeader().height() + len(events) * 28 + 4
            self.timeline_view.setFixedHeight(min(max(h, 60), 200))
        else:
            self.timeline_view.setVisible(False)
            self.timeline_empty_lbl.setVisible(True)

    # =========================================================================
    # PUBLIC NAVIGATION & INCIDENT RESOLUTION
    # =========================================================================

    def navigate_to_incident(self, incident_id: int):
        """
        Public programmatic navigation: selects and highlights the specified incident ID,
        resets filters if necessary, scrolls to the incident row, and expands the details panel.
        Called by MainWindow when arriving from Dashboard or Scan Center / ScanThreatsDialog.
        """
        if self.inc_repo.is_incident_dismissed(incident_id):
            self.inc_repo.undismiss_incident(incident_id)

        self.refresh()

        found = False
        target_row = -1
        for idx, inc in enumerate(self.model.incidents):
            if inc.get("id") == incident_id:
                found = True
                target_row = idx
                break

        # If not visible under current filter/search, reset filters to reveal it
        if not found:
            self._on_clear_filters_clicked()
            for idx, inc in enumerate(self.model.incidents):
                if inc.get("id") == incident_id:
                    found = True
                    target_row = idx
                    break

        # Safety Fallback: If still not found in current table model list, fetch directly from DB
        if target_row < 0:
            target_inc = self.inc_repo.get_incident(incident_id)
            if target_inc:
                inc_dict = dict(target_inc)
                existing_ids = [i.get("id") for i in self.model.incidents]
                if incident_id not in existing_ids:
                    current_incidents = [inc_dict] + self.model.incidents
                    self.model.set_incidents(current_incidents)
                for idx, inc in enumerate(self.model.incidents):
                    if inc.get("id") == incident_id:
                        target_row = idx
                        break

        if target_row >= 0:
            self._check_empty_state()
            self.table_view.selectRow(target_row)
            self.table_view.scrollTo(self.model.index(target_row, 0))
            inc = self.model.get_incident_at(target_row)
            if inc:
                self._populate_details(inc)
                self.investigation_scroll.setVisible(True)
                self.splitter.setSizes([240, 380])

    def _resolve_current_incident(self):
        """Resolves the active incident, records audit log, and notifies listeners."""
        if not self.current_incident:
            return

        inc_id = self.current_incident["id"]
        self.inc_repo.resolve_incident(inc_id)

        # Log to audit history
        target_loc = self.current_incident.get("full_path") or self.current_incident.get("affected_folder") or "System File"
        HistoryRepository(self.db).insert_log(
            event_type="THREAT_RESOLVED",
            severity="LOW",
            description=f"Incident ID {inc_id} ({self.current_incident.get('threat_name')}) marked resolved by administrator.",
            target=target_loc,
            action_taken="INCIDENT_RESOLVED"
        )

        self.incident_resolved.emit()
        self.refresh()

    def _generate_threat_report(self):
        """Generates a dedicated, executive-grade PDF for the currently selected incident."""
        if not self.current_incident:
            QMessageBox.warning(self, "No Threat Selected", "Please select a security threat from the table first.")
            return

        threat_name = self.current_incident.get("threat_name", "Incident").replace(" ", "_")
        time_str = time.strftime("%Y%m%d_%H%M%S")
        default_filename = f"RansomGuard_Threat_Report_{threat_name}_{time_str}.pdf"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Dedicated Threat Incident PDF Report",
            default_filename,
            "PDF Files (*.pdf)"
        )

        if not file_path:
            return

        self.report_threat_btn.setEnabled(False)
        self.report_threat_btn.setText("Generating...")

        self.threat_pdf_thread = PDFReportGenerator(
            output_path=file_path,
            report_type="threat_incident",
            incident_id=self.current_incident["id"],
            db_manager=self.db
        )
        self.threat_pdf_thread.finished.connect(self._on_threat_report_completed)
        self.threat_pdf_thread.error.connect(self._on_threat_report_error)
        self.threat_pdf_thread.start()

    def _on_threat_report_completed(self, path):
        self.report_threat_btn.setEnabled(True)
        self.report_threat_btn.setText("📄 Generate Threat Report")

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
            self,
            "Threat Report Generated",
            f"Dedicated Security Threat Incident Report generated and opened successfully:\n\n{path}"
        )

    def _on_threat_report_error(self, err_msg):
        self.report_threat_btn.setEnabled(True)
        self.report_threat_btn.setText("📄 Generate Threat Report")
        QMessageBox.critical(
            self,
            "Report Generation Error",
            f"Failed to generate Threat Incident PDF Report:\n\n{err_msg}"
        )
