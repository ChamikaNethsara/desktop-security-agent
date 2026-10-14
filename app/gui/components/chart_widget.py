"""
Security Activity Chart Widget
Custom vector QPainter chart matching the bar & line activity chart in the reference design.
"""

from __future__ import annotations
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QWidget
)
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import (
    QPainter, QColor, QFont, QPen, QBrush, QPainterPath, QLinearGradient
)

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_CYAN
)


class ActivityCanvas(QWidget):
    """Draws custom bar and line graph with axis, grid lines and data points."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(180)
        self.days = ["Sep 3", "Sep 4", "Sep 5", "Sep 6", "Sep 7", "Sep 8", "Sep 9"]
        self.bar_values = [38, 48, 42, 60, 56, 45, 52]      # Files scanned
        self.line_values = [25, 28, 35, 45, 38, 32, 34]     # Secrets detected
        self.max_val = 80

    def set_data(self, days: list[str], bars: list[int], lines: list[int]):
        self.days = days
        self.bar_values = bars
        self.line_values = lines
        max_b = max(bars) if bars else 10
        max_l = max(lines) if lines else 10
        self.max_val = max(80, max(max_b, max_l) + 10)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()

        padding_left = 36
        padding_right = 16
        padding_top = 16
        padding_bottom = 32

        plot_w = width - padding_left - padding_right
        plot_h = height - padding_top - padding_bottom

        if plot_w <= 0 or plot_h <= 0:
            return

        # 1. Draw horizontal grid lines & Y-axis labels
        painter.setFont(QFont("Segoe UI", 9))
        y_steps = [0, 20, 40, 60, 80]
        if self.max_val > 80:
            y_steps = [0, int(self.max_val * 0.25), int(self.max_val * 0.5), int(self.max_val * 0.75), int(self.max_val)]

        for y_val in y_steps:
            ratio = y_val / self.max_val
            y_pos = padding_top + plot_h - (ratio * plot_h)

            # Text
            painter.setPen(QColor(TEXT_MUTED))
            painter.drawText(0, int(y_pos) - 8, padding_left - 8, 16, Qt.AlignmentFlag.AlignRight, str(y_val))

            # Grid Line
            painter.setPen(QPen(QColor("#1A2438"), 1, Qt.PenStyle.DashLine))
            painter.drawLine(padding_left, int(y_pos), width - padding_right, int(y_pos))

        n_points = len(self.days)
        if n_points == 0:
            return

        col_width = plot_w / n_points
        bar_width = min(22, col_width * 0.42)

        line_points: list[QPointF] = []

        # 2. Draw bars
        bar_color = QColor("#0078D4")
        bar_brush = QBrush(bar_color)

        for i, (day, val) in enumerate(zip(self.days, self.bar_values)):
            center_x = padding_left + (i + 0.5) * col_width
            ratio = min(1.0, val / self.max_val)
            bar_h = ratio * plot_h
            bar_y = padding_top + plot_h - bar_h

            # Draw bar with rounded top
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(bar_brush)
            painter.drawRoundedRect(
                int(center_x - bar_width / 2),
                int(bar_y),
                int(bar_width),
                int(bar_h),
                4, 4
            )

            # X-axis label
            painter.setPen(QColor(TEXT_MUTED))
            painter.drawText(
                int(center_x - col_width / 2),
                height - padding_bottom + 8,
                int(col_width),
                20,
                Qt.AlignmentFlag.AlignCenter,
                day
            )

        # 3. Draw line curve
        for i, l_val in enumerate(self.line_values):
            center_x = padding_left + (i + 0.5) * col_width
            ratio = min(1.0, l_val / self.max_val)
            l_y = padding_top + plot_h - (ratio * plot_h)
            line_points.append(QPointF(center_x, l_y))

        if len(line_points) > 1:
            line_path = QPainterPath()
            line_path.moveTo(line_points[0])
            for i in range(1, len(line_points)):
                p0 = line_points[i - 1]
                p1 = line_points[i]
                c_x1 = p0.x() + (p1.x() - p0.x()) / 2
                c_x2 = c_x1
                line_path.cubicTo(c_x1, p0.y(), c_x2, p1.y(), p1.x(), p1.y())

            line_pen = QPen(QColor(COLOR_CYAN), 2.5)
            painter.setPen(line_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(line_path)

            # Draw glowing dots
            for pt in line_points:
                # Outer glow
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(6, 182, 212, 100))
                painter.drawEllipse(pt, 6, 6)
                # Inner white point
                painter.setBrush(QColor("#FFFFFF"))
                painter.drawEllipse(pt, 3, 3)


class ChartWidget(QFrame):
    """Full Security Activity card with header, dropdown and canvas."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#ChartWidget {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("ChartWidget")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header Row
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        icon_lbl = QLabel("📊")
        icon_lbl.setStyleSheet("font-size: 16px;")
        header_row.addWidget(icon_lbl)

        title_lbl = QLabel("Security Activity")
        title_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        header_row.addWidget(title_lbl)

        header_row.addStretch()

        self.time_combo = QComboBox()
        self.time_combo.addItems(["Last 7 Days", "Last 14 Days", "Last 30 Days"])
        self.time_combo.setFixedWidth(120)
        header_row.addWidget(self.time_combo)

        layout.addLayout(header_row)

        # Canvas
        self.canvas = ActivityCanvas()
        layout.addWidget(self.canvas)

        # Legend Row
        legend_row = QHBoxLayout()
        legend_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        legend_row.setSpacing(24)

        b_item = QHBoxLayout()
        b_dot = QLabel("●")
        b_dot.setStyleSheet(f"color: #0078D4; font-size: 14px;")
        b_txt = QLabel("Files Scanned")
        b_txt.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; font-weight: 600;")
        b_item.addWidget(b_dot)
        b_item.addWidget(b_txt)
        legend_row.addLayout(b_item)

        l_item = QHBoxLayout()
        l_dot = QLabel("●")
        l_dot.setStyleSheet(f"color: {COLOR_CYAN}; font-size: 14px;")
        l_txt = QLabel("Secrets Detected")
        l_txt.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; font-weight: 600;")
        l_item.addWidget(l_dot)
        l_item.addWidget(l_txt)
        legend_row.addLayout(l_item)

        layout.addLayout(legend_row)
