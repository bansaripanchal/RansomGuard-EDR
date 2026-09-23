"""
RansomGuard EDR — Centralized Visual Theme Manager & Design System
Single source of truth for color tokens, QPalette configuration, and global QSS generation.
Theme Identity: ENTERPRISE DARK NAVY / CHARCOAL EDR (Dark Navy Dominant, Electric Blue Primary Accent, Purple Secondary)
"""

import os
from PySide6.QtGui import QPalette, QColor

# ==============================================================================
# OFFICIAL GLOBAL COLOR SYSTEM TOKENS (Strictly Enforced)
# ==============================================================================
# 1. Dark Navy Environment & Surfaces (85% Dominance)
APP_BACKGROUND       = "#070B16"  # Deep dark navy environment
PAGE_BACKGROUND      = "#090F1C"  # Dark canvas page background
SIDEBAR_BACKGROUND   = "#070B16"  # Integrated dark navy sidebar
SURFACE              = "#0D1422"  # Main card / panel surface
SURFACE_ELEVATED     = "#111A2B"  # Sub-cards, headers, table headers
SURFACE_ACTIVE       = "#17233A"  # Active / selected states, hover surfaces
TABLE_ALT            = "#0F1726"  # Alternating table row background
PURPLE_NAVY          = "#070B16"  # Topbar background alias

# 2. Subtle Navy Borders (No harsh outlines)
BORDER_SUBTLE        = "#1A2940"  # Normal card and container borders
BORDER               = "#1A2940"  # Default panel and control borders
BORDER_HOVER         = "#21334D"  # Subtle hover border
BORDER_ACTIVE        = "#355B8A"  # Active / focused control border
NAVY_BORDER          = "#1A2940"

# 3. Primary UI Accent — Electric Blue (8%)
PRIMARY_BLUE         = "#168BFF"
ELECTRIC_BLUE        = "#168BFF"
BRIGHT_BLUE          = "#38A8FF"
CYAN                 = "#18D7FF"
BLUE_GLOW            = "#168BFF"

# 4. Secondary Accent — Purple (5% Restrained Accent)
SECONDARY_ACCENT     = "#7B3FF2"
PRIMARY_PURPLE       = "#7B3FF2"
BRIGHT_PURPLE        = "#A855F7"
LIGHT_PURPLE         = "#C084FC"
DEEP_PURPLE          = "#1B1030"
DARK_PURPLE          = "#111A2B"
PURPLE_GLOW          = "#8B5CF6"
PURPLE_BORDER        = "#7B3FF2"

# 5. Typography
TEXT_PRIMARY         = "#F4F7FF"  # High-contrast crisp white/light
TEXT_SECONDARY       = "#A9B8D4"  # Muted blue-gray readable secondary
TEXT_MUTED           = "#71809A"  # Dimmed metadata

# 6. Semantic Status Indicators (2% Preserved)
SUCCESS              = "#00E59A"  # Healthy / Active / Clean / Created
WARNING              = "#FFB84D"  # Amber warning / Renamed
DANGER               = "#FF4D67"  # Malicious / Critical alert / Deleted

# Compatibility aliases
BORDER_PURPLE        = BORDER_SUBTLE
BORDER_GLOW          = BORDER_ACTIVE
BRIGHT_PURPLE_BORDER = BORDER_ACTIVE
PURPLE               = PRIMARY_PURPLE


def get_global_qss() -> str:
    """Generates the master global QSS stylesheet bound to RansomGuard enterprise dark navy color tokens."""
    return f"""
/* ==============================================================================
   RANSOMGUARD EDR GLOBAL ENTERPRISE DARK NAVY STYLESHEET
   ============================================================================== */

QMainWindow {{
    background-color: {APP_BACKGROUND};
}}

QWidget {{
    font-family: "Inter", "Segoe UI", -apple-system, sans-serif;
    color: {TEXT_PRIMARY};
    font-size: 13px;
    background: transparent;
}}

QStackedWidget {{
    background-color: {PAGE_BACKGROUND};
}}

/* Scroll Canvas Pages */
QWidget#scrollContent, QWidget#scanScrollContent, QWidget#historyScrollContent, 
QWidget#settingsScrollContent, QWidget#reportsScrollContent, QWidget#aboutScrollContent {{
    background-color: {PAGE_BACKGROUND};
}}

QScrollArea {{
    border: none;
    background-color: {PAGE_BACKGROUND};
}}

/* ------------------------------------------------------------------------------
   SIDEBAR NAVIGATION
   ------------------------------------------------------------------------------ */
QFrame#sidebar {{
    background-color: {SIDEBAR_BACKGROUND};
    border-right: 1px solid {BORDER};
    min-width: 230px;
    max-width: 230px;
}}

QLabel#sidebarTitle {{
    font-size: 16px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    padding: 18px 14px;
    border-bottom: 1px solid {BORDER};
    background: {SIDEBAR_BACKGROUND};
    letter-spacing: 1px;
}}

QPushButton.sidebarButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-left: 4px solid transparent;
    color: {TEXT_MUTED};
    text-align: left;
    padding: 11px 16px;
    font-size: 13px;
    font-weight: 600;
    border-radius: 6px;
    margin: 3px 10px;
}}

QPushButton.sidebarButton:hover {{
    background-color: {SURFACE_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_HOVER};
    border-left: 4px solid {ELECTRIC_BLUE};
}}

QPushButton.sidebarButton:checked {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0E274D, stop:1 #143870);
    color: #FFFFFF;
    font-weight: bold;
    border: 1px solid {BORDER_ACTIVE};
    border-left: 5px solid {ELECTRIC_BLUE};
}}

/* ------------------------------------------------------------------------------
   TOPBAR HEADER
   ------------------------------------------------------------------------------ */
QFrame#topbar {{
    background-color: {SIDEBAR_BACKGROUND};
    border-bottom: 1px solid {BORDER};
    min-height: 58px;
    max-height: 58px;
}}

QLabel#topbarTitle {{
    font-size: 18px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    padding-left: 20px;
    letter-spacing: 0.5px;
}}

/* ------------------------------------------------------------------------------
   CARDS & PANELS (NATURALLY BLENDED DARK NAVY SURFACES)
   ------------------------------------------------------------------------------ */
QFrame.metricCard, QFrame#socAlertsCard, QFrame#socActivityCard, QFrame#dashHeaderCard, 
QFrame#endpointStatusCard, QFrame#socPulseCard, QFrame#existingScanCard, QFrame.cardFrame, 
QFrame.panelFrame, QFrame#clickableAlertFrame, QFrame#driveCard, QFrame#usbDeviceCard, 
QFrame#imageScanCard, QFrame#settingsSectionCard, QFrame#scanEvidenceCard, 
QFrame#investigationHeaderCard, QFrame#investigationSummaryCard, 
QFrame#investigationEvidenceCard, QFrame#investigationTimelineCard, 
QFrame#scanEmptyStateContainer, QFrame.socPanel {{
    background-color: {SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 8px;
    padding: 12px;
}}

QFrame.metricCard:hover, QFrame#socAlertsCard:hover, QFrame#socActivityCard:hover, 
QFrame#endpointStatusCard:hover, QFrame.cardFrame:hover, QFrame.panelFrame:hover, 
QFrame#clickableAlertFrame:hover, QFrame#driveCard:hover, QFrame#usbDeviceCard:hover,
QFrame#settingsSectionCard:hover {{
    border-color: {BORDER_HOVER};
    background-color: {SURFACE_ELEVATED};
}}

QLabel.cardValue {{
    font-size: 24px;
    font-weight: bold;
    color: {TEXT_PRIMARY};
}}

QLabel.cardTitle {{
    font-size: 11px;
    color: {TEXT_MUTED};
    font-weight: bold;
    letter-spacing: 0.5px;
}}

/* ------------------------------------------------------------------------------
   STATUS BADGES
   ------------------------------------------------------------------------------ */
QLabel.statusBadge {{
    border-radius: 4px;
    padding: 3px 8px;
    font-weight: bold;
    font-size: 11px;
}}

QLabel.badgeLow {{
    background-color: rgba(22, 139, 255, 0.15);
    color: {BRIGHT_BLUE};
    border: 1px solid rgba(22, 139, 255, 0.4);
}}

QLabel.badgeMedium {{
    background-color: rgba(255, 184, 77, 0.15);
    color: {WARNING};
    border: 1px solid rgba(255, 184, 77, 0.4);
}}

QLabel.badgeHigh {{
    background-color: rgba(255, 77, 103, 0.15);
    color: {DANGER};
    border: 1px solid rgba(255, 77, 103, 0.4);
}}

QLabel.badgeCritical {{
    background-color: rgba(255, 77, 103, 0.25);
    color: {DANGER};
    border: 1px solid {DANGER};
}}

/* ------------------------------------------------------------------------------
   GLOBAL TABLES (DARK NAVY WITH CRISP BLUE HIGHLIGHTS)
   ------------------------------------------------------------------------------ */
QTableView, QTableWidget {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    gridline-color: {BORDER};
    border-radius: 8px;
    outline: none;
    color: {TEXT_PRIMARY};
    selection-background-color: {SURFACE_ACTIVE};
    selection-color: #FFFFFF;
}}

QTableView::item, QTableWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {BORDER};
}}

QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {SURFACE_ACTIVE};
    color: #FFFFFF;
    border-left: 3px solid {ELECTRIC_BLUE};
    border-bottom: 1px solid {BORDER};
    font-weight: 600;
}}

QTableView::item:hover, QTableWidget::item:hover {{
    background-color: {SURFACE_ELEVATED};
}}

QTableView::item:alternate, QTableWidget::item:alternate {{
    background-color: {TABLE_ALT};
}}

QHeaderView::section {{
    background-color: {SURFACE_ELEVATED};
    color: {TEXT_SECONDARY};
    padding: 9px 12px;
    border: none;
    border-bottom: 1px solid {BORDER};
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 0.5px;
}}

/* ------------------------------------------------------------------------------
   BUTTONS (ELECTRIC BLUE PRIMARY + DARK NAVY SECONDARY)
   ------------------------------------------------------------------------------ */
QPushButton.primaryButton, QPushButton#btnPrimary, QPushButton#btn_scan_now, 
QPushButton#btn_details, QPushButton#btn_run_scan, QPushButton#save_scope_btn {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ELECTRIC_BLUE}, stop:1 {BRIGHT_BLUE});
    border: 1px solid {ELECTRIC_BLUE};
    color: #FFFFFF;
    padding: 8px 18px;
    border-radius: 6px;
    font-weight: bold;
    font-size: 13px;
}}

QPushButton.primaryButton:hover, QPushButton#btnPrimary:hover, 
QPushButton#btn_scan_now:hover, QPushButton#btn_details:hover, QPushButton#btn_run_scan:hover,
QPushButton#save_scope_btn:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {BRIGHT_BLUE}, stop:1 #60B8FF);
    border-color: #60B8FF;
}}

QPushButton.primaryButton:pressed, QPushButton#btnPrimary:pressed, 
QPushButton#btn_scan_now:pressed, QPushButton#btn_details:pressed, QPushButton#btn_run_scan:pressed,
QPushButton#save_scope_btn:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0D6ED4, stop:1 {ELECTRIC_BLUE});
}}

QPushButton.primaryButton:disabled, QPushButton#btnPrimary:disabled, QPushButton#btn_scan_now:disabled {{
    background: {SURFACE_ELEVATED};
    color: {TEXT_MUTED};
    border: 1px solid {BORDER};
}}

QPushButton.secondaryButton {{
    background-color: {SURFACE_ELEVATED};
    border: 1px solid {BORDER};
    color: {TEXT_SECONDARY};
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
}}

QPushButton.secondaryButton:hover {{
    background-color: {SURFACE_ACTIVE};
    border-color: {BORDER_ACTIVE};
    color: #FFFFFF;
}}

QPushButton.actionRedButton {{
    background-color: rgba(255, 77, 103, 0.15);
    border: 1px solid {DANGER};
    color: {DANGER};
    padding: 7px 14px;
    border-radius: 6px;
    font-weight: bold;
}}

QPushButton.actionRedButton:hover {{
    background-color: rgba(255, 77, 103, 0.3);
}}

/* ------------------------------------------------------------------------------
   INPUTS & FORM CONTROLS
   ------------------------------------------------------------------------------ */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 12px;
    color: #FFFFFF;
    selection-background-color: {ELECTRIC_BLUE};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {ELECTRIC_BLUE};
}}

QComboBox {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 12px;
    color: #FFFFFF;
}}

QComboBox:focus, QComboBox:hover {{
    border-color: {BORDER_ACTIVE};
}}

QComboBox QAbstractItemView {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    color: #FFFFFF;
    selection-background-color: {SURFACE_ACTIVE};
    selection-color: {BRIGHT_BLUE};
    outline: none;
    padding: 4px;
}}

/* ------------------------------------------------------------------------------
   LISTS & TREES
   ------------------------------------------------------------------------------ */
QListWidget, QTreeWidget {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 4px;
    color: {TEXT_PRIMARY};
}}

QListWidget::item, QTreeWidget::item {{
    padding: 6px 8px;
    border-radius: 4px;
}}

QListWidget::item:hover, QTreeWidget::item:hover {{
    background-color: {SURFACE_ELEVATED};
}}

QListWidget::item:selected, QTreeWidget::item:selected {{
    background-color: {SURFACE_ACTIVE};
    color: #FFFFFF;
    font-weight: bold;
    border: 1px solid {BORDER_ACTIVE};
    border-left: 3px solid {ELECTRIC_BLUE};
}}

/* ------------------------------------------------------------------------------
   SCROLLBARS
   ------------------------------------------------------------------------------ */
QScrollBar:vertical {{
    border: none;
    background: {PAGE_BACKGROUND};
    width: 8px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background: {BORDER_HOVER};
    min-height: 20px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {ELECTRIC_BLUE}, stop:1 {BRIGHT_BLUE});
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    border: none;
    background: none;
}}

QScrollBar:horizontal {{
    border: none;
    background: {PAGE_BACKGROUND};
    height: 8px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background: {BORDER_HOVER};
    min-width: 20px;
    border-radius: 4px;
}}

QScrollBar::handle:horizontal:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ELECTRIC_BLUE}, stop:1 {BRIGHT_BLUE});
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    border: none;
    background: none;
}}

/* ------------------------------------------------------------------------------
   TABS
   ------------------------------------------------------------------------------ */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    background-color: {SURFACE};
    border-radius: 8px;
}}

QTabBar::tab {{
    background: {SURFACE_ELEVATED};
    border: 1px solid {BORDER};
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 3px;
    color: {TEXT_MUTED};
    font-weight: 600;
}}

QTabBar::tab:selected {{
    background: {SURFACE_ACTIVE};
    border: 1px solid {BORDER_ACTIVE};
    border-bottom: 2px solid {ELECTRIC_BLUE};
    color: #FFFFFF;
    font-weight: bold;
}}

QTabBar::tab:hover {{
    color: {TEXT_PRIMARY};
}}

/* ------------------------------------------------------------------------------
   PROGRESS BARS
   ------------------------------------------------------------------------------ */
QProgressBar {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 4px;
    text-align: center;
    color: #FFFFFF;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ELECTRIC_BLUE}, stop:1 {BRIGHT_BLUE});
    border-radius: 3px;
}}

/* ------------------------------------------------------------------------------
   DIALOGS & MESSAGES
   ------------------------------------------------------------------------------ */
QDialog, QMessageBox {{
    background-color: {APP_BACKGROUND};
    color: {TEXT_PRIMARY};
}}

QSplitter::handle {{
    background-color: {BORDER};
    height: 4px;
    width: 4px;
}}

QSplitter::handle:hover {{
    background-color: {BORDER_ACTIVE};
}}

/* ------------------------------------------------------------------------------
   CHECKBOXES
   ------------------------------------------------------------------------------ */
QCheckBox {{
    color: {TEXT_PRIMARY};
    font-size: 13px;
    spacing: 6px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER};
    border-radius: 4px;
    background: {SURFACE};
}}

QCheckBox::indicator:hover {{
    border-color: {BORDER_ACTIVE};
}}

QCheckBox::indicator:checked {{
    background: {ELECTRIC_BLUE};
    border-color: {ELECTRIC_BLUE};
}}
"""


def apply_theme(app) -> None:
    """Configures global QApplication palette and loads master RansomGuard enterprise dark navy theme stylesheet."""
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(APP_BACKGROUND))
    dark_palette.setColor(QPalette.WindowText, QColor(TEXT_PRIMARY))
    dark_palette.setColor(QPalette.Base, QColor(SURFACE))
    dark_palette.setColor(QPalette.AlternateBase, QColor(TABLE_ALT))
    dark_palette.setColor(QPalette.ToolTipBase, QColor(SURFACE_ELEVATED))
    dark_palette.setColor(QPalette.ToolTipText, QColor("#FFFFFF"))
    dark_palette.setColor(QPalette.Text, QColor(TEXT_PRIMARY))
    dark_palette.setColor(QPalette.Button, QColor(SURFACE_ELEVATED))
    dark_palette.setColor(QPalette.ButtonText, QColor("#FFFFFF"))
    dark_palette.setColor(QPalette.BrightText, QColor(ELECTRIC_BLUE))
    dark_palette.setColor(QPalette.Highlight, QColor(ELECTRIC_BLUE))
    dark_palette.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
    app.setPalette(dark_palette)

    # Generate master stylesheet content
    qss_content = get_global_qss()
    app.setStyleSheet(qss_content)

    # Persist sync copy into ui/styles.qss file for external loaders
    app_dir = os.path.dirname(os.path.abspath(__file__))
    styles_path = os.path.join(app_dir, "styles.qss")
    try:
        with open(styles_path, "w", encoding="utf-8") as f:
            f.write(qss_content)
    except Exception:
        pass
