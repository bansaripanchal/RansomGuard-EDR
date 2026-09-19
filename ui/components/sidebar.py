from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QPushButton, QButtonGroup
from PySide6.QtCore import Signal, Qt

class Sidebar(QFrame):
    page_changed = Signal(int)

    def __init__(self, parent=None):
        super(Sidebar, self).__init__(parent)
        self.setObjectName("sidebar")
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Title / Brand Logo area
        self.title_label = QLabel("🛡️ RANSOMGUARD", self)
        self.title_label.setObjectName("sidebarTitle")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.title_label)

        # Button Group for mutual exclusion selection
        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)

        # Navigation buttons mapping to page index
        self.nav_items = [
            ("📊 Dashboard", 0),
            ("🚨 Threat Repository", 2),
            ("🔍 Scan Center", 3),
            ("💾 USB Protection", 8),
            ("🛡️ Live Protection", 1),
            ("📄 Reports & Audit", 4),
            ("🕒 History Log", 5),
            ("⚙️ Settings", 6),
            ("ℹ️ About", 7)
        ]

        self.buttons = []
        for text, index in self.nav_items:
            btn = QPushButton(text, self)
            btn.setCheckable(True)
            btn.setObjectName(f"navBtn_{index}")
            btn.setProperty("class", "sidebarButton")
            btn.setCursor(Qt.PointingHandCursor)
            
            # Hook signal
            btn.clicked.connect(lambda checked, idx=index: self.page_changed.emit(idx))
            
            self.btn_group.addButton(btn, index)
            self.layout.addWidget(btn)
            self.buttons.append(btn)

        # Default select Dashboard
        if self.buttons:
            self.buttons[0].setChecked(True)

        self.layout.addStretch()

        # Version label at bottom
        self.version_label = QLabel("v1.0.0 Stable", self)
        self.version_label.setStyleSheet("color: #9CA3AF; padding: 15px; font-size: 11px;")
        self.version_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.version_label)

    def set_active_page(self, index):
        """Forces sidebar active button to match page index programmatically."""
        btn = self.btn_group.button(index)
        if btn:
            btn.setChecked(True)
