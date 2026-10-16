"""
Risk Score View
Component 3: Static Configuration Risk Auditor interface.
Audits configuration files (Dockerfiles, JSON, YAML, etc.), calculates risk scores,
and displays security findings with remediation recommendations.
"""

from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QFrame, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_CYAN
)
from app.gui.components.badge import SeverityBadge, StatusBadge

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class RiskScoreView(QWidget):
    """Component 3 Risk Score & Configuration Auditor screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Header
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("🛡️ Static Configuration Risk Auditor")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Component 3: Inspect project configs against CFG rules (Docker, YAML, JSON) & compute risk score.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        # Audit Controls Card
        ctrl_card = QFrame()
        ctrl_card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 14px;
            }}
        """)
        cc_layout = QHBoxLayout(ctrl_card)
        cc_layout.setSpacing(10)

        lbl = QLabel("Target Directory:")
        lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 600;")
        cc_layout.addWidget(lbl)

        self.path_edit = QLineEdit(str(self.bridge.current_target_dir))
        cc_layout.addWidget(self.path_edit, stretch=1)

        browse_btn = QPushButton("📁 Browse...")
        browse_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E2E4A;
                color: #FFFFFF;
                border: 1px solid #3B527E;
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: #2A3F66;
                border-color: {ACCENT_BLUE};
            }}
        """)
        browse_btn.clicked.connect(self.browse_directory)
        cc_layout.addWidget(browse_btn)

        run_btn = QPushButton("🚀 Run Full Audit")
        run_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
                border: 1px solid #38BDF8;
                border-radius: 8px;
                font-weight: 700;
                padding: 8px 20px;
            }}
            QPushButton:hover {{
                background-color: #006ED3;
                border-color: #60A5FA;
            }}
        """)
        run_btn.clicked.connect(self.run_audit)
        cc_layout.addWidget(run_btn)

        layout.addWidget(ctrl_card)

        # Score Summary Cards
        score_row = QHBoxLayout()
        score_row.setSpacing(16)

        # Card 1: Score & Category
        self.score_card = QFrame()
        self.score_card.setStyleSheet(f"background-color: {BG_CARD}; border: 1px solid {BORDER_COLOR}; border-radius: 10px; padding: 14px;")
        sc_layout = QVBoxLayout(self.score_card)
        sc_layout.setSpacing(4)
        sc_lbl = QLabel("SECURITY RISK SCORE")
        sc_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-weight: 700;")
        sc_layout.addWidget(sc_lbl)

        self.score_val = QLabel("28.00 / 100")
        self.score_val.setStyleSheet(f"color: {COLOR_CYAN}; font-size: 26px; font-weight: bold;")
        sc_layout.addWidget(self.score_val)

        self.cat_badge = StatusBadge("Critical Risk")
        sc_layout.addWidget(self.cat_badge, alignment=Qt.AlignmentFlag.AlignLeft)
        score_row.addWidget(self.score_card, stretch=1)

        # Card 2: Quick Presets
        presets_card = QFrame()
        presets_card.setStyleSheet(f"background-color: {BG_CARD}; border: 1px solid {BORDER_COLOR}; border-radius: 10px; padding: 14px;")
        pc_layout = QVBoxLayout(presets_card)
        pc_lbl = QLabel("QUICK SCAN PRESETS")
        pc_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; font-weight: 700;")
        pc_layout.addWidget(pc_lbl)

        btn_row = QHBoxLayout()
        preset_style = f"""
            QPushButton {{
                background-color: #1E2D48;
                color: #FFFFFF;
                border: 1px solid #384F78;
                border-radius: 6px;
                padding: 7px 12px;
                font-weight: 600;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: #283C66;
                border-color: {ACCENT_BLUE};
                color: #FFFFFF;
            }}
        """

        vuln_btn = QPushButton("Scan Vulnerable Test Configs")
        vuln_btn.setStyleSheet(preset_style)
        vuln_btn.clicked.connect(lambda: self.scan_preset("test_configs/vulnerable"))
        btn_row.addWidget(vuln_btn)

        safe_btn = QPushButton("Scan Safe Test Configs")
        safe_btn.setStyleSheet(preset_style)
        safe_btn.clicked.connect(lambda: self.scan_preset("test_configs/safe"))
        btn_row.addWidget(safe_btn)

        all_btn = QPushButton("Scan Entire Repository")
        all_btn.setStyleSheet(preset_style)
        all_btn.clicked.connect(lambda: self.scan_preset("."))
        btn_row.addWidget(all_btn)
        pc_layout.addLayout(btn_row)
        score_row.addWidget(presets_card, stretch=2)

        layout.addLayout(score_row)

        # Findings Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Severity", "Rule ID", "Title / Risk Issue", "Target File", "Recommendation"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 110)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.verticalHeader().setMinimumSectionSize(36)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)

        # Connect bridge signal
        self.bridge.audit_completed.connect(self.display_audit_result)

        # Run initial audit on test_configs/vulnerable
        self.run_audit()

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Project Directory to Audit", str(self.bridge.project_root))
        if dir_path:
            self.path_edit.setText(dir_path)

    def scan_preset(self, rel_path: str):
        target = self.bridge.project_root / rel_path
        self.path_edit.setText(str(target))
        self.run_audit()

    def run_audit(self):
        target_str = self.path_edit.text().strip()
        target = Path(target_str).expanduser().resolve()
        if not target.exists():
            QMessageBox.warning(self, "Directory Not Found", f"Directory does not exist:\n{target}")
            return
        self.bridge.run_project_audit(target)

    def display_audit_result(self, res: dict):
        score = res.get("risk_score", 100.0)
        category = res.get("risk_category", "Excellent")
        findings = res.get("findings", [])

        self.score_val.setText(f"{score:.2f} / 100")
        self.cat_badge.set_status(category)

        self.table.setRowCount(len(findings))
        for row_idx, f in enumerate(findings):
            self.table.setRowHeight(row_idx, 42)
            sev = getattr(f, "severity", "High")
            rule_id = getattr(f, "rule_id", "CFG-???")
            title = getattr(f, "title", "Configuration Risk")
            file_name = Path(getattr(f, "file_path", "")).name
            rec = getattr(f, "recommendation", "")

            # Badge
            badge = SeverityBadge(sev)
            b_box = QWidget()
            bl = QHBoxLayout(b_box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bl.addWidget(badge)
            self.table.setCellWidget(row_idx, 0, b_box)

            # Rule ID
            r_item = QTableWidgetItem(rule_id)
            r_item.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 1, r_item)

            # Title
            t_item = QTableWidgetItem(title)
            t_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 2, t_item)

            # File
            f_item = QTableWidgetItem(file_name)
            f_item.setForeground(QColor(ACCENT_BLUE))
            self.table.setItem(row_idx, 3, f_item)

            # Recommendation
            rec_item = QTableWidgetItem(rec)
            rec_item.setForeground(QColor(TEXT_SECONDARY))
            self.table.setItem(row_idx, 4, rec_item)
