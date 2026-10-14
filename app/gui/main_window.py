"""
Main Application Window
Assembles the Left Sidebar navigation, Top Header bar, and Central QStackedWidget views.
"""

from __future__ import annotations
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel,
    QStackedWidget, QFrame, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from app.gui.theme import (
    BG_MAIN, BG_SIDEBAR, BG_CARD, BORDER_COLOR, BORDER_SUBTLE, TEXT_PRIMARY,
    TEXT_SECONDARY, TEXT_MUTED, ACCENT_BLUE, COLOR_GREEN, COLOR_RED, APP_STYLESHEET
)
from app.gui.backend_bridge import BackendBridge
from app.gui.views.dashboard_view import DashboardView
from app.gui.views.alerts_view import AlertsView
from app.gui.views.isolated_secrets_view import IsolatedSecretsView
from app.gui.views.risk_score_view import RiskScoreView
from app.gui.views.history_view import HistoryView
from app.gui.views.reports_view import ReportsView
from app.gui.views.settings_view import SettingsView


class NavButton(QPushButton):
    """Sidebar navigation item with icon, label and optional badge."""

    def __init__(self, icon_str: str, text: str, badge_count: Optional[int] = None, parent=None):
        super().__init__(parent)
        self.icon_str = icon_str
        self.nav_text = text
        self.badge_count = badge_count
        self.is_active = False

        self.setCheckable(False)
        self.setMinimumHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(14, 8, 14, 8)
        self.layout.setSpacing(12)

        self.icon_lbl = QLabel(icon_str)
        self.icon_lbl.setStyleSheet("font-size: 15px; background: transparent;")
        self.layout.addWidget(self.icon_lbl)

        self.text_lbl = QLabel(text)
        self.text_lbl.setStyleSheet("font-size: 13px; font-weight: 500; background: transparent;")
        self.layout.addWidget(self.text_lbl)

        self.layout.addStretch()

        if badge_count and badge_count > 0:
            self.badge_lbl = QLabel(str(badge_count))
            self.badge_lbl.setStyleSheet(f"""
                QLabel {{
                    background-color: {COLOR_RED};
                    color: #FFFFFF;
                    border-radius: 9px;
                    padding: 1px 6px;
                    font-size: 10px;
                    font-weight: bold;
                }}
            """)
            self.layout.addWidget(self.badge_lbl)
        else:
            self.badge_lbl = None

        self.set_active(False)

    def set_active(self, active: bool):
        self.is_active = active
        if active:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ACCENT_BLUE};
                    border: none;
                    border-radius: 8px;
                    text-align: left;
                }}
            """)
            self.text_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF; background: transparent;")
            self.icon_lbl.setStyleSheet("font-size: 15px; color: #FFFFFF; background: transparent;")
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    border: none;
                    border-radius: 8px;
                    text-align: left;
                }}
                QPushButton:hover {{
                    background-color: #121A2B;
                }}
            """)
            self.text_lbl.setStyleSheet(f"font-size: 13px; font-weight: 500; color: {TEXT_SECONDARY}; background: transparent;")
            self.icon_lbl.setStyleSheet(f"font-size: 15px; color: {TEXT_SECONDARY}; background: transparent;")

    def update_badge(self, count: int):
        if count > 0:
            if not self.badge_lbl:
                self.badge_lbl = QLabel(str(count))
                self.badge_lbl.setStyleSheet(f"""
                    QLabel {{
                        background-color: {COLOR_RED};
                        color: #FFFFFF;
                        border-radius: 9px;
                        padding: 1px 6px;
                        font-size: 10px;
                        font-weight: bold;
                    }}
                """)
                self.layout.addWidget(self.badge_lbl)
            else:
                self.badge_lbl.setText(str(count))
                self.badge_lbl.show()
        elif self.badge_lbl:
            self.badge_lbl.hide()


class MainWindow(QMainWindow):
    """Main SecureGuard Desktop Security Agent Window."""

    def __init__(self, bridge: Optional[BackendBridge] = None):
        super().__init__()
        self.bridge = bridge or BackendBridge()

        self.setWindowTitle("SecureGuard — Desktop Security Agent")
        self.resize(1280, 840)
        self.setMinimumSize(1024, 680)
        self.setStyleSheet(APP_STYLESHEET)

        # Central layout (Sidebar on left, Main content on right)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # -------------------------------------------------------------
        # Left Sidebar
        # -------------------------------------------------------------
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)

        # -------------------------------------------------------------
        # Right Main Container (Top Bar + QStackedWidget)
        # -------------------------------------------------------------
        content_container = QWidget()
        content_container.setStyleSheet(f"background-color: {BG_MAIN};")
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Top Bar
        top_bar = self.create_top_bar()
        content_layout.addWidget(top_bar)

        # QStackedWidget
        self.stack = QStackedWidget()
        self.dashboard_view = DashboardView(self.bridge)
        self.dashboard_view.navigate_to_tab.connect(self.switch_to_tab_by_name)

        self.alerts_view = AlertsView(self.bridge)
        self.vault_view = IsolatedSecretsView(self.bridge)
        self.risk_view = RiskScoreView(self.bridge)
        self.history_view = HistoryView(self.bridge)
        self.reports_view = ReportsView(self.bridge)
        self.settings_view = SettingsView(self.bridge)

        self.stack.addWidget(self.dashboard_view)    # 0
        self.stack.addWidget(self.alerts_view)       # 1
        self.stack.addWidget(self.vault_view)        # 2
        self.stack.addWidget(self.risk_view)         # 3
        self.stack.addWidget(self.history_view)      # 4
        self.stack.addWidget(self.reports_view)      # 5
        self.stack.addWidget(self.settings_view)     # 6

        content_layout.addWidget(self.stack)
        main_layout.addWidget(content_container, stretch=1)

        # Set default active tab = Dashboard
        self.set_active_tab(0)

        # Connect bridge signals for real-time status and actual badge counts
        self.bridge.monitoring_changed.connect(self.update_topbar_status)
        self.bridge.stats_updated.connect(self.on_stats_updated)
        self.on_stats_updated(self.bridge.get_dashboard_data())

    def create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_SIDEBAR};
                border-right: 1px solid {BORDER_COLOR};
            }}
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 20, 16, 16)
        layout.setSpacing(6)

        # App Brand Header
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)

        logo_lbl = QLabel("🛡️")
        logo_lbl.setStyleSheet("font-size: 26px; background: transparent;")
        brand_row.addWidget(logo_lbl)

        brand_text_box = QVBoxLayout()
        brand_text_box.setSpacing(1)

        app_title = QLabel("SecureGuard")
        app_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #FFFFFF; background: transparent;")
        brand_text_box.addWidget(app_title)

        app_sub = QLabel("Desktop Security Agent")
        app_sub.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED}; background: transparent;")
        brand_text_box.addWidget(app_sub)

        brand_row.addLayout(brand_text_box)
        brand_row.addStretch()
        layout.addLayout(brand_row)

        layout.addSpacing(20)

        # Navigation Buttons
        self.nav_buttons: list[NavButton] = []

        nav_items = [
            ("⊞", "Dashboard", None),
            ("🔔", "Live Alerts", 3),
            ("🔒", "Isolated Secrets", None),
            ("🛡️", "Risk Score", None),
            ("🕒", "Scan History", None),
            ("📑", "Reports", None),
            ("⚙️", "Settings", None),
        ]

        for idx, (icon, text, badge) in enumerate(nav_items):
            btn = NavButton(icon, text, badge)
            btn.clicked.connect(lambda _, index=idx: self.set_active_tab(index))
            layout.addWidget(btn)
            self.nav_buttons.append(btn)

        layout.addStretch()

        # Footer
        footer_box = QVBoxLayout()
        footer_box.setSpacing(2)
        v_lbl = QLabel("Version 1.0.0")
        v_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; background: transparent;")
        b_lbl = QLabel("SecureGuard")
        b_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-weight: bold; background: transparent;")
        footer_box.addWidget(v_lbl)
        footer_box.addWidget(b_lbl)
        layout.addLayout(footer_box)

        return sidebar

    def create_top_bar(self) -> QWidget:
        top_bar = QFrame()
        top_bar.setFixedHeight(72)
        top_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_MAIN};
                border-bottom: 1px solid {BORDER_COLOR};
                padding: 0px 24px;
            }}
        """)

        layout = QHBoxLayout(top_bar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)

        # Title + Subtitle
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title_box.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self.page_title = QLabel("Security Overview")
        self.page_title.setStyleSheet("font-size: 20px; font-weight: 700; color: #FFFFFF;")
        title_box.addWidget(self.page_title)

        self.page_subtitle = QLabel("Monitor security events and manage your project's security posture.")
        self.page_subtitle.setStyleSheet(f"font-size: 12px; color: {TEXT_SECONDARY};")
        title_box.addWidget(self.page_subtitle)

        layout.addLayout(title_box)
        layout.addStretch()

        # Right Controls: Status Pill
        self.status_pill = QFrame()
        self.status_pill.setStyleSheet(f"""
            QFrame {{
                background-color: #064E3B;
                border: 1px solid {COLOR_GREEN}55;
                border-radius: 18px;
                padding: 4px 14px;
            }}
        """)
        sp_layout = QHBoxLayout(self.status_pill)
        sp_layout.setContentsMargins(6, 4, 6, 4)
        sp_layout.setSpacing(8)

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 12px;")
        sp_layout.addWidget(self.status_dot)

        status_text_col = QVBoxLayout()
        status_text_col.setSpacing(0)
        self.status_text_top = QLabel("System Protected")
        self.status_text_top.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 11px; font-weight: 700;")
        self.status_text_bot = QLabel("Monitoring Active")
        self.status_text_bot.setStyleSheet(f"color: #A7F3D0; font-size: 10px;")
        status_text_col.addWidget(self.status_text_top)
        status_text_col.addWidget(self.status_text_bot)
        sp_layout.addLayout(status_text_col)

        layout.addWidget(self.status_pill)

        # Bell notification icon button
        self.bell_btn = QPushButton("🔔")
        self.bell_btn.setFixedSize(36, 36)
        self.bell_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.bell_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 18px;
                font-size: 13px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                border-color: {ACCENT_BLUE};
            }}
        """)
        self.bell_btn.clicked.connect(lambda: self.set_active_tab(1))
        layout.addWidget(self.bell_btn)

        # User profile
        profile_frame = QFrame()
        profile_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 18px;
                padding: 4px 10px;
            }}
        """)
        pf_layout = QHBoxLayout(profile_frame)
        pf_layout.setContentsMargins(6, 4, 8, 4)
        pf_layout.setSpacing(8)

        avatar = QLabel("👤")
        avatar.setStyleSheet("font-size: 14px;")
        pf_layout.addWidget(avatar)

        user_lbl = QLabel("Developer ⌵")
        user_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
        pf_layout.addWidget(user_lbl)

        layout.addWidget(profile_frame)

        return top_bar

    def update_topbar_status(self, is_monitoring: bool):
        if is_monitoring:
            self.status_pill.setStyleSheet(f"""
                QFrame {{
                    background-color: #064E3B;
                    border: 1px solid {COLOR_GREEN}55;
                    border-radius: 18px;
                    padding: 4px 14px;
                }}
            """)
            self.status_dot.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 12px;")
            self.status_text_top.setText("System Protected")
            self.status_text_top.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 11px; font-weight: 700;")
            self.status_text_bot.setText("Monitoring Active")
        else:
            self.status_pill.setStyleSheet(f"""
                QFrame {{
                    background-color: #1E293B;
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 18px;
                    padding: 4px 14px;
                }}
            """)
            self.status_dot.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
            self.status_text_top.setText("Watcher Idle")
            self.status_text_top.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; font-weight: 700;")
            self.status_text_bot.setText("Click to Monitor")

    def set_active_tab(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == index)

        headers = [
            ("Security Overview", "Monitor security events and manage your project's security posture."),
            ("Live Alerts", "Real-time secret scanner detections and quick isolation actions."),
            ("Isolated Secrets Vault", "AES-256-GCM encrypted credentials vault with rollback capabilities."),
            ("Static Risk Score", "Component 3: Automated Docker, JSON, and YAML misconfiguration analysis."),
            ("Scan History", "Full audit log of detected findings, remediation events, and audits."),
            ("Security Audit Reports", "Generate and export executive-ready PDF audit reports."),
            ("Settings & Custom Rules", "Configure pattern_rules.yaml and file_rules.yaml for custom detection."),
        ]
        if index < len(headers):
            self.page_title.setText(headers[index][0])
            self.page_subtitle.setText(headers[index][1])

    def switch_to_tab_by_name(self, name: str):
        mapping = {
            "dashboard": 0,
            "alerts": 1,
            "vault": 2,
            "risk": 3,
            "history": 4,
            "reports": 5,
            "settings": 6,
        }
        idx = mapping.get(name, 0)
        self.set_active_tab(idx)

    def on_stats_updated(self, data: dict):
        """Update navigation badges and top bar notification count with 100% actual numbers."""
        secrets_count = data.get("secrets_detected", 0)
        isolated_count = data.get("isolated_secrets", 0)

        # Update Live Alerts badge
        if len(self.nav_buttons) > 1:
            self.nav_buttons[1].update_badge(secrets_count)

        # Update Isolated Secrets badge
        if len(self.nav_buttons) > 2:
            self.nav_buttons[2].update_badge(isolated_count)

        # Update top bar bell button with actual alert badge
        if hasattr(self, "bell_btn"):
            if secrets_count > 0:
                self.bell_btn.setText(f"🔔 {secrets_count}")
                self.bell_btn.setFixedWidth(56)
                self.bell_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #450A0A;
                        color: #EF4444;
                        border: 1px solid #EF444466;
                        border-radius: 18px;
                        font-size: 11px;
                        font-weight: 700;
                    }}
                    QPushButton:hover {{
                        background-color: #EF4444;
                        color: #FFFFFF;
                    }}
                """)
            else:
                self.bell_btn.setText("🔔")
                self.bell_btn.setFixedSize(36, 36)
                self.bell_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {BG_CARD};
                        border: 1px solid {BORDER_COLOR};
                        border-radius: 18px;
                        font-size: 13px;
                    }}
                    QPushButton:hover {{
                        border-color: {ACCENT_BLUE};
                    }}
                """)

