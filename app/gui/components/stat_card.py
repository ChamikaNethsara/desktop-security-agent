"""
Stat Card Component
Interactive, minimal summary metric cards linking directly to their respective views.
"""

from __future__ import annotations
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel, QWidget
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPainter, QColor, QFont, QPen, QBrush

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN, COLOR_RED, COLOR_PURPLE, COLOR_YELLOW
)


class IconCircle(QWidget):
    """Clean icon container."""

    def __init__(self, icon_type: str, bg_color: str, fg_color: str, parent=None):
        super().__init__(parent)
        self.icon_type = icon_type
        self.bg_color = QColor(bg_color)
        self.fg_color = QColor(fg_color)
        self.setFixedSize(46, 46)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(self.bg_color))
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 10, 10)

        painter.setPen(QPen(self.fg_color, 2))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))

        sym = "📁"
        if self.icon_type == "folder":
            sym = "📁"
        elif self.icon_type == "key":
            sym = "🔑"
        elif self.icon_type == "lock":
            sym = "🔒"
        elif self.icon_type == "shield":
            sym = "🛡️"

        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, sym)


class StatCard(QFrame):
    """Clickable metric card linking directly to views."""
    clicked = Signal()

    def __init__(
        self,
        icon_type: str,
        icon_bg: str,
        icon_fg: str,
        title: str,
        value: str,
        subtitle: str,
        trend: str,
        trend_positive: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#StatCard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
            QFrame#StatCard:hover {{
                border: 1px solid {ACCENT_BLUE};
                background-color: #162035;
            }}
        """)
        self.setObjectName("StatCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(124)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 14, 16, 14)
        main_layout.setSpacing(8)

        # Top row: Icon + Title & Value
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        icon_widget = IconCircle(icon_type, icon_bg, icon_fg)
        top_row.addWidget(icon_widget, alignment=Qt.AlignmentFlag.AlignTop)

        info_col = QVBoxLayout()
        info_col.setSpacing(1)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet(f"""
            color: {TEXT_MUTED};
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.8px;
        """)
        info_col.addWidget(title_lbl)

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            font-size: 24px;
            font-weight: 700;
        """)
        info_col.addWidget(self.value_lbl)

        top_row.addLayout(info_col)
        top_row.addStretch()
        main_layout.addLayout(top_row)

        # Bottom row: Subtitle + Action Hint
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(8)

        self.sub_lbl = QLabel(subtitle)
        self.sub_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        bottom_row.addWidget(self.sub_lbl)
        bottom_row.addStretch()

        trend_color = COLOR_GREEN if trend_positive else COLOR_RED
        self.trend_lbl = QLabel(trend)
        self.trend_lbl.setStyleSheet(f"""
            color: {trend_color};
            font-size: 11px;
            font-weight: 700;
        """)
        bottom_row.addWidget(self.trend_lbl)

        main_layout.addLayout(bottom_row)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def update_value(self, value: str, subtitle: str | None = None, trend: str | None = None):
        self.value_lbl.setText(value)
        if subtitle:
            self.sub_lbl.setText(subtitle)
        if trend:
            self.trend_lbl.setText(trend)
