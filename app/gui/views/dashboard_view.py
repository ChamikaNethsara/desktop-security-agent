"""
Dashboard Overview View
Clean, minimal, high-contrast security dashboard displaying 100% actual data.
Fully linked with interactive stat cards, project picker, real-time watcher and quick actions.
"""

from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from app.gui.theme import (
    BG_MAIN, BG_CARD, BORDER_COLOR, BORDER_SUBTLE, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_CYAN, COLOR_PURPLE
)
from app.gui.components.stat_card import StatCard
from app.gui.components.chart_widget import ChartWidget
from app.gui.components.gauge_widget import RiskGaugeWidget
from app.gui.components.badge import SeverityBadge, StatusBadge

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class RecentAlertsCard(QFrame):
    """Recent Alerts card in middle column with clickable rows."""
    view_all_clicked = Signal()
    alert_clicked = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#RecentAlertsCard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("RecentAlertsCard")

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(18, 16, 18, 16)
        self.layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        icon = QLabel("⚠️")
        icon.setStyleSheet("font-size: 15px;")
        header.addWidget(icon)

        title = QLabel("Recent Alerts")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        header.addWidget(title)

        header.addStretch()

        view_all = QPushButton("View All →")
        view_all.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E293B;
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                color: {ACCENT_BLUE};
                font-size: 12px;
                font-weight: 700;
                padding: 4px 10px;
            }}
            QPushButton:hover {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
            }}
        """)
        view_all.clicked.connect(self.view_all_clicked.emit)
        header.addWidget(view_all)

        self.layout.addLayout(header)

        # List items container
        self.items_container = QVBoxLayout()
        self.items_container.setSpacing(8)
        self.layout.addLayout(self.items_container)
        self.layout.addStretch()

    def populate_alerts(self, alerts: list[dict]):
        while self.items_container.count():
            item = self.items_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not alerts:
            lbl = QLabel("✅ No secret alerts found in current scan target.")
            lbl.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 12px; padding: 18px 0; font-weight: 600;")
            self.items_container.addWidget(lbl)
            return

        for a in alerts[:5]:
            row_frame = QFrame()
            row_frame.setCursor(Qt.CursorShape.PointingHandCursor)
            row_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #101726;
                    border: 1px solid {BORDER_SUBTLE};
                    border-radius: 8px;
                    padding: 4px 8px;
                }}
                QFrame:hover {{
                    border-color: {ACCENT_BLUE};
                    background-color: #152238;
                }}
            """)
            r_layout = QHBoxLayout(row_frame)
            r_layout.setContentsMargins(8, 6, 8, 6)
            r_layout.setSpacing(10)

            # Badge
            badge = SeverityBadge(a.get("severity", "MEDIUM"))
            r_layout.addWidget(badge)

            # Info
            info_col = QVBoxLayout()
            info_col.setSpacing(2)
            name_lbl = QLabel(a.get("pattern_name", "Security Finding"))
            name_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 12px; font-weight: 700;")
            info_col.addWidget(name_lbl)

            file_p = Path(a.get("file_path", "")).name or "config"
            line_no = a.get("line_number", 1)
            loc_lbl = QLabel(f"{file_p} • Line {line_no}")
            loc_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
            info_col.addWidget(loc_lbl)

            r_layout.addLayout(info_col)
            r_layout.addStretch()

            # Time
            time_lbl = QLabel("Recent")
            det_at = a.get("detected_at")
            if det_at:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(det_at.replace("Z", "+00:00"))
                    time_lbl.setText(dt.strftime("%I:%M %p"))
                except Exception:
                    pass
            time_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
            r_layout.addWidget(time_lbl)

            chevron = QLabel("›")
            chevron.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 18px; font-weight: bold;")
            r_layout.addWidget(chevron)

            # Click to navigate to alerts
            row_frame.mousePressEvent = lambda ev, item=a: self.view_all_clicked.emit()
            self.items_container.addWidget(row_frame)


class QuickActionsCard(QFrame):
    """High-contrast Quick Actions 2x2 grid."""
    start_monitoring_clicked = Signal()
    generate_report_clicked = Signal()
    refresh_clicked = Signal()
    settings_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#QuickActionsCard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("QuickActionsCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(6)
        icon = QLabel("⚡")
        icon.setStyleSheet("font-size: 15px;")
        header.addWidget(icon)
        title = QLabel("Quick Actions")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        # 2x2 Buttons Grid with high contrast styling
        grid = QGridLayout()
        grid.setSpacing(10)

        # 1. Start Monitoring
        self.monitor_btn = QPushButton("▶  Start Monitoring")
        self.monitor_btn.setMinimumHeight(56)
        self.monitor_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.monitor_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
                border: 1px solid #3B82F6;
                border-radius: 8px;
                font-weight: 700;
                font-size: 12px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #1D4ED8;
            }}
        """)
        self.monitor_btn.clicked.connect(self.start_monitoring_clicked.emit)
        grid.addWidget(self.monitor_btn, 0, 0)

        # 2. Generate Report
        self.report_btn = QPushButton("📄  Generate Report")
        self.report_btn.setMinimumHeight(56)
        self.report_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.report_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E293B;
                color: #FFFFFF;
                border: 1px solid #334155;
                border-radius: 8px;
                font-weight: 700;
                font-size: 12px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #334155;
                border-color: {ACCENT_BLUE};
            }}
        """)
        self.report_btn.clicked.connect(self.generate_report_clicked.emit)
        grid.addWidget(self.report_btn, 0, 1)

        # 3. Refresh / Scan
        self.refresh_btn = QPushButton("🔄  Rescan Project")
        self.refresh_btn.setMinimumHeight(56)
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E293B;
                color: #FFFFFF;
                border: 1px solid #334155;
                border-radius: 8px;
                font-weight: 700;
                font-size: 12px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #334155;
                border-color: {COLOR_GREEN};
            }}
        """)
        self.refresh_btn.clicked.connect(self.refresh_clicked.emit)
        grid.addWidget(self.refresh_btn, 1, 0)

        # 4. Settings
        self.settings_btn = QPushButton("⚙️  Configure Rules")
        self.settings_btn.setMinimumHeight(56)
        self.settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E293B;
                color: #FFFFFF;
                border: 1px solid #334155;
                border-radius: 8px;
                font-weight: 700;
                font-size: 12px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #334155;
                border-color: #94A3B8;
            }}
        """)
        self.settings_btn.clicked.connect(self.settings_clicked.emit)
        grid.addWidget(self.settings_btn, 1, 1)

        layout.addLayout(grid)

    def set_monitoring_state(self, is_monitoring: bool):
        if is_monitoring:
            self.monitor_btn.setText("⏹  Stop Monitoring")
            self.monitor_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #DC2626;
                    color: #FFFFFF;
                    border: 1px solid #EF4444;
                    border-radius: 8px;
                    font-weight: 700;
                    font-size: 12px;
                    padding: 10px;
                }}
                QPushButton:hover {{
                    background-color: #B91C1C;
                }}
            """)
        else:
            self.monitor_btn.setText("▶  Start Monitoring")
            self.monitor_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ACCENT_BLUE};
                    color: #FFFFFF;
                    border: 1px solid #3B82F6;
                    border-radius: 8px;
                    font-weight: 700;
                    font-size: 12px;
                    padding: 10px;
                }}
                QPushButton:hover {{
                    background-color: #1D4ED8;
                }}
            """)


class SystemStatusCard(QFrame):
    """System Status indicators list in bottom right."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#SystemStatusCard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("SystemStatusCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 14px;")
        header.addWidget(dot)

        title = QLabel("System Status")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        self.status_labels = {}
        for key, icon, name in [
            ("scanner", "⚡", "Scanner Engine"),
            ("masking", "🔒", "Masking Engine"),
            ("auditor", "🛡️", "Risk Auditor"),
            ("database", "🗄️", "SQLite Vault"),
        ]:
            row = QHBoxLayout()
            row.setSpacing(8)

            ic_lbl = QLabel(icon)
            ic_lbl.setStyleSheet("font-size: 13px;")
            row.addWidget(ic_lbl)

            lbl = QLabel(name)
            lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            row.addWidget(lbl)
            row.addStretch()

            st_val = QLabel("Active")
            st_val.setStyleSheet(f"color: {COLOR_GREEN}; font-size: 12px; font-weight: 700;")
            row.addWidget(st_val)

            layout.addLayout(row)
            self.status_labels[key] = st_val

        layout.addStretch()

        footer = QHBoxLayout()
        clock_ic = QLabel("🕒")
        clock_ic.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        footer.addWidget(clock_ic)

        self.last_updated = QLabel("Last Updated: Just now")
        self.last_updated.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        footer.addWidget(self.last_updated)
        footer.addStretch()
        layout.addLayout(footer)

    def update_status(self, status_dict: dict):
        if "scanner" in status_dict:
            st = status_dict["scanner"]
            self.status_labels["scanner"].setText(st)
            self.status_labels["scanner"].setStyleSheet(
                f"color: {COLOR_GREEN if st == 'Active' else '#94A3B8'}; font-size: 12px; font-weight: 700;"
            )
        if "last_updated" in status_dict:
            self.last_updated.setText(f"Last Updated: {status_dict['last_updated']}")


class SecurityActivityTable(QFrame):
    """Last events table in bottom row."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame#SecurityActivityTable {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
        """)
        self.setObjectName("SecurityActivityTable")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        header = QHBoxLayout()
        icon = QLabel("📈")
        icon.setStyleSheet("font-size: 15px;")
        header.addWidget(icon)

        title = QLabel("Security Activity (Recent Events)")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Time", "Event", "Details", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(170)

        layout.addWidget(self.table)

    def populate_events(self, events: list[dict]):
        self.table.setRowCount(0)
        if not events:
            self.table.setRowCount(1)
            item = QTableWidgetItem("No security events recorded yet.")
            item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(0, 2, item)
            return

        self.table.setRowCount(len(events))
        for row_idx, ev in enumerate(events):
            t_str = "Recent"
            det_at = ev.get("detected_at")
            if det_at:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(det_at.replace("Z", "+00:00"))
                    t_str = dt.strftime("%I:%M %p")
                except Exception:
                    pass

            file_name = Path(ev.get("file_path", "")).name or "config"
            details = f"{ev.get('pattern_name', 'Secret')} in {file_name}"
            sev = ev.get("severity", "medium")

            t_item = QTableWidgetItem(t_str)
            t_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 0, t_item)

            ev_item = QTableWidgetItem("Secret Detected")
            ev_item.setForeground(QColor(TEXT_PRIMARY))
            self.table.setItem(row_idx, 1, ev_item)

            det_item = QTableWidgetItem(details)
            det_item.setForeground(QColor(TEXT_SECONDARY))
            self.table.setItem(row_idx, 2, det_item)

            badge = SeverityBadge(sev)
            badge.setFixedHeight(24)
            badge_container = QWidget()
            b_layout = QHBoxLayout(badge_container)
            b_layout.setContentsMargins(4, 2, 4, 2)
            b_layout.addWidget(badge)
            self.table.setCellWidget(row_idx, 3, badge_container)


class DashboardView(QWidget):
    """Main Dashboard View with interactive project selector and 100% actual data."""

    navigate_to_tab = Signal(str)

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        content_widget = QWidget()
        self.main_layout = QVBoxLayout(content_widget)
        self.main_layout.setContentsMargins(24, 16, 24, 24)
        self.main_layout.setSpacing(18)

        # -------------------------------------------------------------
        # 0. Minimal Target Project Bar
        # -------------------------------------------------------------
        project_bar = QFrame()
        project_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 10px 16px;
            }}
        """)
        pb_layout = QHBoxLayout(project_bar)
        pb_layout.setContentsMargins(4, 4, 4, 4)
        pb_layout.setSpacing(12)

        p_lbl = QLabel("📁 Target Project:")
        p_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        pb_layout.addWidget(p_lbl)

        self.project_path_lbl = QLabel(str(self.bridge.current_target_dir))
        self.project_path_lbl.setStyleSheet(f"color: {ACCENT_BLUE}; font-family: Consolas; font-size: 12px; font-weight: 600;")
        pb_layout.addWidget(self.project_path_lbl, stretch=1)

        # Change Folder button
        change_dir_btn = QPushButton("Change Folder...")
        change_dir_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        change_dir_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E293B;
                color: #FFFFFF;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 600;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #334155;
                border-color: {ACCENT_BLUE};
            }}
        """)
        change_dir_btn.clicked.connect(self.choose_target_folder)
        pb_layout.addWidget(change_dir_btn)

        # Scan Now button
        scan_now_btn = QPushButton("⚡ Scan Project Now")
        scan_now_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        scan_now_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
                border: 1px solid #3B82F6;
                border-radius: 6px;
                padding: 6px 18px;
                font-weight: 700;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #1D4ED8;
            }}
        """)
        scan_now_btn.clicked.connect(self.scan_current_project)
        pb_layout.addWidget(scan_now_btn)

        self.main_layout.addWidget(project_bar)

        # -------------------------------------------------------------
        # 1. Top Row: 4 Interactive Stat Cards (Fully Linked)
        # -------------------------------------------------------------
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        self.card_files = StatCard(
            icon_type="folder",
            icon_bg="#0F2D4A",
            icon_fg=ACCENT_BLUE,
            title="FILES SCANNED",
            value="0",
            subtitle="Click to view file audit",
            trend="Active",
            trend_positive=True
        )
        self.card_files.clicked.connect(lambda: self.navigate_to_tab.emit("risk"))
        top_row.addWidget(self.card_files)

        self.card_secrets = StatCard(
            icon_type="key",
            icon_bg="#3D1424",
            icon_fg="#FB7185",
            title="SECRETS DETECTED",
            value="0",
            subtitle="Click to view live alerts",
            trend="Action Required",
            trend_positive=False
        )
        self.card_secrets.clicked.connect(lambda: self.navigate_to_tab.emit("alerts"))
        top_row.addWidget(self.card_secrets)

        self.card_isolated = StatCard(
            icon_type="lock",
            icon_bg="#0A362B",
            icon_fg=COLOR_GREEN,
            title="ISOLATED SECRETS",
            value="0",
            subtitle="Click to inspect vault",
            trend="Protected",
            trend_positive=True
        )
        self.card_isolated.clicked.connect(lambda: self.navigate_to_tab.emit("vault"))
        top_row.addWidget(self.card_isolated)

        self.card_risk = StatCard(
            icon_type="shield",
            icon_bg="#2D164D",
            icon_fg=COLOR_PURPLE,
            title="RISK SCORE",
            value="100 / 100",
            subtitle="Click for score details",
            trend="Audit",
            trend_positive=True
        )
        self.card_risk.clicked.connect(lambda: self.navigate_to_tab.emit("risk"))
        top_row.addWidget(self.card_risk)

        self.main_layout.addLayout(top_row)

        # -------------------------------------------------------------
        # 2. Middle Row: Activity Chart + Recent Alerts + Risk Gauge
        # -------------------------------------------------------------
        mid_row = QHBoxLayout()
        mid_row.setSpacing(16)

        self.chart_widget = ChartWidget()
        mid_row.addWidget(self.chart_widget, stretch=45)

        self.recent_alerts = RecentAlertsCard()
        self.recent_alerts.view_all_clicked.connect(lambda: self.navigate_to_tab.emit("alerts"))
        mid_row.addWidget(self.recent_alerts, stretch=30)

        self.risk_gauge = RiskGaugeWidget()
        mid_row.addWidget(self.risk_gauge, stretch=25)

        self.main_layout.addLayout(mid_row)

        # -------------------------------------------------------------
        # 3. Bottom Row: Table + Quick Actions + System Status
        # -------------------------------------------------------------
        bot_row = QHBoxLayout()
        bot_row.setSpacing(16)

        self.activity_table = SecurityActivityTable()
        bot_row.addWidget(self.activity_table, stretch=48)

        self.quick_actions = QuickActionsCard()
        self.quick_actions.start_monitoring_clicked.connect(self._toggle_monitoring)
        self.quick_actions.generate_report_clicked.connect(lambda: self.navigate_to_tab.emit("reports"))
        self.quick_actions.refresh_clicked.connect(self.scan_current_project)
        self.quick_actions.settings_clicked.connect(lambda: self.navigate_to_tab.emit("settings"))
        bot_row.addWidget(self.quick_actions, stretch=27)

        self.system_status = SystemStatusCard()
        bot_row.addWidget(self.system_status, stretch=25)

        self.main_layout.addLayout(bot_row)

        # Wrap in scroll
        scroll.setWidget(content_widget)
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

        # Connect signals
        self.bridge.stats_updated.connect(self.refresh_dashboard)
        self.bridge.monitoring_changed.connect(self.quick_actions.set_monitoring_state)

        # Load initial actual data
        self.refresh_dashboard(self.bridge.get_dashboard_data())

    def choose_target_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder to Scan", str(self.bridge.current_target_dir))
        if folder:
            self.project_path_lbl.setText(folder)
            self.bridge.current_target_dir = Path(folder)
            self.scan_current_project()

    def scan_current_project(self):
        self.bridge.scan_target_project(self.bridge.current_target_dir)

    def _toggle_monitoring(self):
        self.bridge.toggle_monitoring(self.bridge.current_target_dir)

    def refresh_dashboard(self, data: dict):
        self.project_path_lbl.setText(data.get("target_directory", str(self.bridge.current_target_dir)))

        # Actual data updates
        files_scanned = data.get("files_scanned", 0)
        secrets_detected = data.get("secrets_detected", 0)
        isolated_secrets = data.get("isolated_secrets", 0)
        risk_score = data.get("risk_score", 100)
        risk_category = data.get("risk_category", "Excellent")

        self.card_files.update_value(f"{files_scanned:,}", subtitle="Eligible files inspected")
        self.card_secrets.update_value(
            f"{secrets_detected}",
            subtitle=f"{max(0, secrets_detected - isolated_secrets)} unmasked",
            trend="Active" if secrets_detected > 0 else "Clean"
        )
        self.card_isolated.update_value(f"{isolated_secrets}", subtitle="Encrypted in vault")
        self.card_risk.update_value(f"{risk_score} / 100", subtitle=f"{risk_category}")

        # Update Chart with actual data
        cd = data.get("chart_data", {})
        if cd and "days" in cd:
            self.chart_widget.canvas.set_data(cd["days"], cd.get("bars", []), cd.get("lines", []))

        # Update Recent Alerts
        alerts = data.get("recent_alerts", [])
        self.recent_alerts.populate_alerts(alerts)

        # Update Risk Gauge
        bd = data.get("risk_breakdown", {})
        self.risk_gauge.update_risk(
            score=risk_score,
            secrets_count=bd.get("secrets", 0),
            config_count=bd.get("config", 0),
            ports_count=bd.get("ports", 0),
        )

        # Update Activity Table
        events = data.get("last_events", [])
        self.activity_table.populate_events(events)

        # Update System Status
        status = data.get("status", {})
        self.system_status.update_status(status)
