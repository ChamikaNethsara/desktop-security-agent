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
        self.setFixedSize(92, 26)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_severity(severity)

    def set_severity(self, severity: str):
        colors = get_severity_colors(severity)
        text_color = colors[0]
        bg_color = colors[1]
        border_color = colors[2] if len(colors) > 2 else f"{text_color}66"

        sev_text = str(severity).upper()
        self.setText(sev_text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-radius: 6px;
                padding: 2px 4px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.6px;
                qproperty-alignment: AlignCenter;
            }}
        """)


class StatusBadge(QLabel):
    """Pill badge for lifecycle status (e.g. Detected, Masked, Rolled Back)."""

    def __init__(self, status: str, parent=None):
        super().__init__(parent)
        self.setFixedSize(94, 26)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_status(status)

    def set_status(self, status: str):
        st = str(status).lower()
        if st in ("masked", "isolated", "resolved", "excellent", "active", "connected", "protected"):
            text_color, bg_color, border_color = "#34D399", "#064E3B", "#10B981"
        elif st in ("detected", "critical"):
            text_color, bg_color, border_color = "#FF6B6B", "#4A1116", "#EF4444"
        elif st in ("rolled_back", "warning", "high"):
            text_color, bg_color, border_color = "#FBBF24", "#451A03", "#F59E0B"
        elif st in ("moderate", "medium"):
            text_color, bg_color, border_color = "#FCD34D", "#3B2B05", "#EAB308"
        else:
            text_color, bg_color, border_color = "#94A3B8", "#1E293B", "#475569"

        display_text = str(status).replace("_", " ").title()
        self.setText(display_text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-radius: 6px;
                padding: 2px 4px;
                font-size: 11px;
                font-weight: 600;
                qproperty-alignment: AlignCenter;
            }}
        """)
