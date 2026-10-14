"""
Desktop Security Agent - Theme & Styling
Modern dark aesthetic matching SecureGuard UI design.
"""

from __future__ import annotations
from PySide6.QtGui import QColor, QFont

# Color Tokens
BG_MAIN = "#0B111E"
BG_SIDEBAR = "#080D17"
BG_CARD = "#131B2E"
BG_CARD_HOVER = "#182239"
BG_INPUT = "#0D1525"
BORDER_COLOR = "#1E2B45"
BORDER_SUBTLE = "#172338"

TEXT_PRIMARY = "#FFFFFF"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"

ACCENT_BLUE = "#0084FF"
ACCENT_BLUE_HOVER = "#0072DC"
ACCENT_BLUE_LIGHT = "#38BDF8"

COLOR_GREEN = "#10B981"
COLOR_GREEN_BG = "#064E3B"
COLOR_RED = "#EF4444"
COLOR_RED_BG = "#7F1D1D"
COLOR_YELLOW = "#F59E0B"
COLOR_YELLOW_BG = "#78350F"
COLOR_PURPLE = "#8B5CF6"
COLOR_PURPLE_BG = "#4C1D95"
COLOR_CYAN = "#06B6D4"


def get_severity_colors(severity: str) -> tuple[str, str]:
    """Returns (text_color, background_color) for severity pill."""
    sev = str(severity).lower()
    if sev in ("critical",):
        return (COLOR_RED, "#3B1115")
    elif sev in ("high",):
        return (COLOR_YELLOW, "#3B2610")
    elif sev in ("medium",):
        return ("#FBBF24", "#372B10")
    elif sev in ("low", "info"):
        return (ACCENT_BLUE_LIGHT, "#0F2847")
    return (TEXT_SECONDARY, "#1A2436")


APP_STYLESHEET = f"""
QMainWindow {{
    background-color: {BG_MAIN};
    color: {TEXT_PRIMARY};
}}

QWidget {{
    background-color: transparent;
    color: {TEXT_PRIMARY};
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}}

/* Scroll bars */
QScrollBar:vertical {{
    background: {BG_MAIN};
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: #25334D;
    min-height: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT_BLUE};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {BG_MAIN};
    height: 8px;
    margin: 0px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: #25334D;
    min-width: 24px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {ACCENT_BLUE};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Inputs & Edits */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {BG_INPUT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    padding: 8px 12px;
    selection-background-color: {ACCENT_BLUE};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {ACCENT_BLUE};
}}

/* Combo Box */
QComboBox {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 12px;
}}
QComboBox:hover {{
    border: 1px solid {ACCENT_BLUE};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    selection-background-color: {ACCENT_BLUE};
    selection-color: #FFFFFF;
    outline: none;
    border-radius: 6px;
    padding: 4px;
}}

/* Push Buttons */
QPushButton {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {BG_CARD_HOVER};
    border-color: {ACCENT_BLUE};
}}
QPushButton:pressed {{
    background-color: #0E1829;
}}
QPushButton:disabled {{
    color: {TEXT_MUTED};
    border-color: {BORDER_SUBTLE};
}}

/* Primary Action Button */
QPushButton.primary-btn {{
    background-color: {ACCENT_BLUE};
    color: #FFFFFF;
    border: none;
    font-weight: 600;
}}
QPushButton.primary-btn:hover {{
    background-color: {ACCENT_BLUE_HOVER};
}}
QPushButton.primary-btn:pressed {{
    background-color: #005DB3;
}}

/* Danger Action Button */
QPushButton.danger-btn {{
    background-color: #991B1B;
    color: #FFFFFF;
    border: none;
    font-weight: 600;
}}
QPushButton.danger-btn:hover {{
    background-color: {COLOR_RED};
}}

/* Tables */
QTableWidget {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_COLOR};
    border-radius: 10px;
    gridline-color: {BORDER_SUBTLE};
    color: {TEXT_PRIMARY};
    selection-background-color: rgba(0, 132, 255, 0.2);
    selection-color: {TEXT_PRIMARY};
    outline: none;
}}
QTableWidget::item {{
    padding: 10px 8px;
    border-bottom: 1px solid {BORDER_SUBTLE};
}}
QTableWidget::item:selected {{
    background-color: rgba(0, 132, 255, 0.18);
}}
QHeaderView::section {{
    background-color: #101726;
    color: {TEXT_MUTED};
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    padding: 8px;
    border: none;
    border-bottom: 1px solid {BORDER_COLOR};
}}

/* Tooltips */
QToolTip {{
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid {BORDER_COLOR};
    background-color: {BG_CARD};
    border-radius: 8px;
}}
QTabBar::tab {{
    background-color: {BG_MAIN};
    color: {TEXT_SECONDARY};
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
}}
QTabBar::tab:selected {{
    background-color: {BG_CARD};
    color: {ACCENT_BLUE};
    font-weight: 600;
}}
QTabBar::tab:hover {{
    color: {TEXT_PRIMARY};
}}

/* Checkboxes */
QCheckBox {{
    color: {TEXT_PRIMARY};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {BORDER_COLOR};
    background-color: {BG_INPUT};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT_BLUE};
    border-color: {ACCENT_BLUE};
}}
"""
