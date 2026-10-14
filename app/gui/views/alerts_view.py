"""
Live Alerts View
Allows inspecting all detected secrets, filtering by severity and status,
and applying Component 2 masking + AES-256 isolation directly with preview.
"""

from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QDialog, QMessageBox, QDialogButtonBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW
)
from app.gui.components.badge import SeverityBadge, StatusBadge

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class MaskDialog(QDialog):
    """Modal dialog to preview and apply secret masking."""

    def __init__(self, file_path: str, line_number: int, finding_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Mask & Isolate Secret (Component 2)")
        self.resize(520, 360)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: #0F172A;
                color: {TEXT_PRIMARY};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # Header
        title = QLabel("🔒 Isolate Secret into AES-256-GCM Vault")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        layout.addWidget(title)

        desc = QLabel(
            "This will redact the hardcoded secret from the live configuration file, "
            "replace it with an environment variable placeholder (${...}), and store the "
            "ciphertext in the local encrypted vault."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(desc)

        # File & Line
        info_box = QFrame()
        info_box.setStyleSheet(f"background-color: #1E293B; border-radius: 8px; padding: 10px;")
        info_layout = QVBoxLayout(info_box)
        info_layout.setSpacing(4)
        info_layout.addWidget(QLabel(f"Target File: <b>{file_path}</b>"))
        info_layout.addWidget(QLabel(f"Line Number: <b>{line_number}</b> | Pattern: <b>{finding_name}</b>"))
        layout.addWidget(info_box)

        # Variable Name input
        var_row = QHBoxLayout()
        var_lbl = QLabel("Variable Name:")
        var_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 600;")
        self.var_edit = QLineEdit("APP_SECRET_TOKEN")
        var_row.addWidget(var_lbl)
        var_row.addWidget(self.var_edit)
        layout.addLayout(var_row)

        # Secret value input (for isolation)
        sec_row = QHBoxLayout()
        sec_lbl = QLabel("Secret to Redact:")
        sec_lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; font-weight: 600;")
        self.sec_edit = QLineEdit()
        self.sec_edit.setPlaceholderText("Enter secret value to redact from line...")
        sec_row.addWidget(sec_lbl)
        sec_row.addWidget(self.sec_edit)
        layout.addLayout(sec_row)

        # Buttons
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Apply Mask & Encrypt")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def get_data(self) -> tuple[str, str]:
        return self.var_edit.text().strip(), self.sec_edit.text()


class AlertsView(QWidget):
    """Live Alerts management screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Top Bar
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Live Security Alerts")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Review real-time secret detections, inspect locations and isolate credentials.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()

        self.refresh_btn = QPushButton("🔄 Refresh Alerts")
        self.refresh_btn.clicked.connect(self.load_alerts)
        top_bar.addWidget(self.refresh_btn)
        layout.addLayout(top_bar)

        # Filters Bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(12)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Search by file, pattern, or category...")
        self.search_edit.textChanged.connect(self.apply_filter)
        filter_bar.addWidget(self.search_edit, stretch=2)

        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.sev_filter.currentTextChanged.connect(self.apply_filter)
        filter_bar.addWidget(self.sev_filter)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "detected", "masked", "ignored", "false_positive"])
        self.status_filter.currentTextChanged.connect(self.apply_filter)
        filter_bar.addWidget(self.status_filter)

        layout.addLayout(filter_bar)

        # Alerts Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Severity", "Pattern Name", "Category", "File & Line", "Confidence", "Status", "Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)

        self.all_findings: list[dict] = []
        self.load_alerts()

    def load_alerts(self):
        self.all_findings = self.bridge.list_findings(limit=200)
        self.apply_filter()

    def apply_filter(self):
        query = self.search_edit.text().strip().lower()
        sev_choice = self.sev_filter.currentText().lower()
        st_choice = self.status_filter.currentText().lower()

        filtered = []
        for f in self.all_findings:
            f_sev = str(f.get("severity", "")).lower()
            f_st = str(f.get("status", "")).lower()
            f_name = str(f.get("pattern_name", "")).lower()
            f_path = str(f.get("file_path", "")).lower()
            f_cat = str(f.get("category", "")).lower()

            if sev_choice != "all severities" and f_sev != sev_choice:
                continue
            if st_choice != "all statuses" and f_st != st_choice:
                continue
            if query and not (query in f_name or query in f_path or query in f_cat):
                continue
            filtered.append(f)

        self.table.setRowCount(len(filtered))
        for row_idx, f in enumerate(filtered):
            # Severity Badge
            badge = SeverityBadge(f.get("severity", "medium"))
            badge_box = QWidget()
            bl = QHBoxLayout(badge_box)
            bl.setContentsMargins(4, 2, 4, 2)
            bl.addWidget(badge)
            self.table.setCellWidget(row_idx, 0, badge_box)

            # Pattern Name
            name_item = QTableWidgetItem(f.get("pattern_name", "Secret"))
            name_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 1, name_item)

            # Category
            cat_item = QTableWidgetItem(f.get("category", "General").title())
            cat_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 2, cat_item)

            # File & Line
            file_name = Path(f.get("file_path", "")).name
            loc_item = QTableWidgetItem(f"{file_name} : Line {f.get('line_number', 1)}")
            loc_item.setForeground(QColor(ACCENT_BLUE))
            self.table.setItem(row_idx, 3, loc_item)

            # Confidence
            conf_val = f.get("confidence", 0.0)
            conf_item = QTableWidgetItem(f"{int(conf_val * 100)}%")
            conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 4, conf_item)

            # Status Badge
            st_badge = StatusBadge(f.get("status", "detected"))
            st_box = QWidget()
            stl = QHBoxLayout(st_box)
            stl.setContentsMargins(4, 2, 4, 2)
            stl.addWidget(st_badge)
            self.table.setCellWidget(row_idx, 5, st_box)

            # Action Buttons
            action_box = QWidget()
            act_layout = QHBoxLayout(action_box)
            act_layout.setContentsMargins(2, 2, 2, 2)
            act_layout.setSpacing(6)

            finding_id = f["id"]
            if f.get("status") != "masked":
                mask_btn = QPushButton("🔒 Mask & Isolate")
                mask_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #064E3B;
                        color: #34D399;
                        border: 1px solid #10B98155;
                        border-radius: 6px;
                        padding: 3px 8px;
                        font-size: 11px;
                        font-weight: 600;
                    }}
                    QPushButton:hover {{
                        background-color: #10B981;
                        color: #FFFFFF;
                    }}
                """)
                mask_btn.clicked.connect(lambda _, item=f: self.handle_mask_finding(item))
                act_layout.addWidget(mask_btn)

            ignore_btn = QPushButton("Ignore")
            ignore_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #1E293B;
                    color: {TEXT_MUTED};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 6px;
                    padding: 3px 8px;
                    font-size: 11px;
                }}
                QPushButton:hover {{
                    color: {TEXT_PRIMARY};
                }}
            """)
            ignore_btn.clicked.connect(lambda _, f_id=finding_id: self.handle_ignore_finding(f_id))
            act_layout.addWidget(ignore_btn)

            self.table.setCellWidget(row_idx, 6, action_box)

    def handle_mask_finding(self, finding: dict):
        file_path = finding.get("file_path", "")
        line_num = finding.get("line_number", 1)
        finding_id = finding["id"]
        pattern_name = finding.get("pattern_name", "Secret")

        dlg = MaskDialog(file_path, line_num, pattern_name, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            var_name, secret_val = dlg.get_data()
            if not secret_val:
                QMessageBox.warning(self, "Missing Secret", "Please enter the secret string to redact.")
                return

            try:
                # Apply mask
                res = self.bridge.apply_secret_mask(
                    finding_id=finding_id,
                    file_path=file_path,
                    line_number=line_num,
                    secret_value=secret_val,
                    var_name=var_name,
                )
                QMessageBox.information(
                    self,
                    "Masking Applied",
                    f"Successfully masked secret in {Path(file_path).name}.\n"
                    f"Placeholder: ${{{var_name.upper()}}}\n"
                    f"Isolated Secret ID: {res['isolation_id']}\n"
                    f"AES-256 encrypted ciphertext stored securely in vault."
                )
                self.load_alerts()
            except Exception as e:
                QMessageBox.critical(self, "Masking Error", f"Failed to mask secret:\n{e}")

    def handle_ignore_finding(self, finding_id: int):
        self.bridge.update_finding_status(finding_id, "ignored", note="Ignored by user via dashboard")
        self.load_alerts()
