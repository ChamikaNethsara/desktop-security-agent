"""
Severity & Status Pill Badge Widget
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel
from app.gui.theme import get_severity_colors, COLOR_GREEN, ACCENT_BLUE_LIGHT


class SeverityBadge(QLabel):
    """Clean rounded pill badge for displaying finding severities."""

    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self.set_severity(severity)

    def set_severity(self, severity: str):
        text_color, bg_color = get_severity_colors(severity)
        sev_text = str(severity).upper()
        self.setText(sev_text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: {bg_color};
                border: 1px solid {text_color}44;
                border-radius: 6px;
                padding: 3px 8px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
        """)


class StatusBadge(QLabel):
    """Pill badge for lifecycle status (e.g. Detected, Masked, Rolled Back)."""

    def __init__(self, status: str, parent=None):
        super().__init__(parent)
        self.set_status(status)

    def set_status(self, status: str):
        st = str(status).lower()
        if st in ("masked", "isolated", "resolved", "excellent", "active", "connected", "protected"):
            text_color, bg_color = "#34D399", "#064E3B"
        elif st in ("detected", "critical"):
            text_color, bg_color = "#F87171", "#450A0A"
        elif st in ("rolled_back", "warning", "high"):
            text_color, bg_color = "#FBBF24", "#451A03"
        elif st in ("moderate", "medium"):
            text_color, bg_color = "#FCD34D", "#3B2B05"
        else:
            text_color, bg_color = "#94A3B8", "#1E293B"

        display_text = str(status).replace("_", " ").title()
        self.setText(display_text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: {bg_color};
                border: 1px solid {text_color}55;
                border-radius: 6px;
                padding: 3px 8px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)
