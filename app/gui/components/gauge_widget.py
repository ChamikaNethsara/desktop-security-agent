"""
Overall Risk Score Gauge Widget
Draws circular donut progress arc, score label, category pill and risk breakdown table.
"""

from __future__ import annotations
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QWidget
)
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import (
    QPainter, QColor, QFont, QPen, QBrush
)

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_CYAN
)


class DonutGauge(QWidget):
    """Draws a circular arc gauge with percentage fill."""

    def __init__(self, score: int = 28, max_score: int = 100, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 140)
        self.score = score
        self.max_score = max_score

    def set_score(self, score: int):
        self.score = max(0, min(self.max_score, score))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        margin = 12
        rect = QRectF(margin, margin, w - 2 * margin, h - 2 * margin)

        pen_width = 10

        # Background track
        bg_pen = QPen(QColor("#1A2538"), pen_width, Qt.PenStyle.SolidLine)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawArc(rect, 0, 360 * 16)

        # Progress Arc (Starts from top = 90 deg, goes clockwise)
        # Choose color according to risk
        if self.score <= 30:
            arc_color = QColor(COLOR_CYAN)
        elif self.score <= 60:
            arc_color = QColor(COLOR_YELLOW)
        else:
            arc_color = QColor(COLOR_RED)

        progress_angle = int((self.score / self.max_score) * 360 * 16)
        fg_pen = QPen(arc_color, pen_width, Qt.PenStyle.SolidLine)
        fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(fg_pen)
        painter.drawArc(rect, 90 * 16, -progress_angle)

        # Center Text: Score
        painter.setPen(QColor(TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        painter.drawText(0, 36, w, 34, Qt.AlignmentFlag.AlignCenter, str(self.score))

        # Center Subtext: / 100
        painter.setPen(QColor(TEXT_MUTED))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        painter.drawText(0, 72, w, 20, Qt.AlignmentFlag.AlignCenter, f"/ {self.max_score}")


class RiskGaugeWidget(QFrame):
    """Overall Risk Score Card."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#RiskGaugeWidget {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("RiskGaugeWidget")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        # Title
        title_lbl = QLabel("Overall Risk Score")
        title_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        layout.addWidget(title_lbl)

        # Gauge in Center
        gauge_container = QHBoxLayout()
        gauge_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.gauge = DonutGauge(score=28)
        gauge_container.addWidget(self.gauge)
        layout.addLayout(gauge_container)

        # Pill badge
        pill_container = QHBoxLayout()
        pill_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk_pill = QLabel("LOW RISK")
        self.risk_pill.setStyleSheet(f"""
            QLabel {{
                color: {COLOR_GREEN};
                background-color: #064E3B;
                border: 1px solid {COLOR_GREEN}66;
                border-radius: 12px;
                padding: 4px 14px;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.5px;
            }}
        """)
        pill_container.addWidget(self.risk_pill)
        layout.addLayout(pill_container)

        # Risk Breakdown section
        breakdown_title = QLabel("Risk Breakdown")
        breakdown_title.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-weight: 700; margin-top: 6px;")
        layout.addWidget(breakdown_title)

        self.breakdown_items = {}
        for item_key, item_name, default_val in [
            ("secrets", "Exposed Secrets", "10"),
            ("config", "Configuration Issues", "12"),
            ("ports", "Open Ports", "6"),
            ("total", "Total Risk", "28"),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(item_name)
            lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            val_lbl = QLabel(default_val)
            val_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val_lbl)
            layout.addLayout(row)
            self.breakdown_items[item_key] = val_lbl

    def update_risk(self, score: int, secrets_count: int, config_count: int, ports_count: int):
        self.gauge.set_score(score)
        total_risk = score
        self.breakdown_items["secrets"].setText(str(secrets_count))
        self.breakdown_items["config"].setText(str(config_count))
        self.breakdown_items["ports"].setText(str(ports_count))
        self.breakdown_items["total"].setText(str(total_risk))

        if score <= 30:
            pill_text = "LOW RISK"
            color = COLOR_GREEN
            bg = "#064E3B"
        elif score <= 60:
            pill_text = "MODERATE RISK"
            color = COLOR_YELLOW
            bg = "#78350F"
        else:
            pill_text = "CRITICAL RISK"
            color = COLOR_RED
            bg = "#7F1D1D"

        self.risk_pill.setText(pill_text)
        self.risk_pill.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {bg};
                border: 1px solid {color}66;
                border-radius: 12px;
                padding: 4px 14px;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.5px;
            }}
        """)
