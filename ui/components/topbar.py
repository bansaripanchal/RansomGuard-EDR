import os
import socket
import sys
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel
from PySide6.QtCore import Qt

class Topbar(QFrame):
    def __init__(self, parent=None):
        super(Topbar, self).__init__(parent)
        self.setObjectName("topbar")
        
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 0)

        # Title of currently selected page
        self.title_label = QLabel("Dashboard", self)
        self.title_label.setObjectName("topbarTitle")
        self.layout.addWidget(self.title_label)

        self.layout.addStretch()

        # Status badge for live protection
        self.shield_badge = QLabel("🛡️ PROTECTION: ACTIVE", self)
        self.shield_badge.setObjectName("shieldBadge")
        self.shield_badge.setStyleSheet("""
            background-color: rgba(0, 229, 154, 0.12); 
            color: #00E59A; 
            border: 1px solid rgba(0, 229, 154, 0.35);
            border-radius: 4px;
            padding: 5px 10px;
            font-weight: bold;
            font-size: 11px;
        """)
        self.layout.addWidget(self.shield_badge)

    def set_page_title(self, title):
        self.title_label.setText(title)

    def update_protection_status(self, is_enabled):
        if is_enabled:
            self.shield_badge.setText("🛡️ PROTECTION: ACTIVE")
            self.shield_badge.setStyleSheet("""
                background-color: rgba(0, 229, 154, 0.12); 
                color: #00E59A; 
                border: 1px solid rgba(0, 229, 154, 0.35);
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 11px;
            """)
        else:
            self.shield_badge.setText("⚠️ PROTECTION: INACTIVE")
            self.shield_badge.setStyleSheet("""
                background-color: rgba(255, 77, 103, 0.12); 
                color: #FF4D67; 
                border: 1px solid rgba(255, 77, 103, 0.35);
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 11px;
            """)
        # Repaint to enforce visual update
        self.shield_badge.update()
