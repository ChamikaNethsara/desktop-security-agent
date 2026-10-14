"""
Scan History View
Full chronological audit trail of detections, masking events, and audits.
"""

from __future__ import annotations
import csv
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, ACCENT_BLUE
)
from app.gui.components.badge import SeverityBadge, StatusBadge

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class HistoryView(QWidget):
    """Scan History & Remediation audit log screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Header
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("🕒 Scan & Remediation History")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Append-only audit trail of security scans, detected secrets, and isolation lifecycles.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()

        export_btn = QPushButton("📥 Export to CSV")
        export_btn.clicked.connect(self.export_csv)
        top_bar.addWidget(export_btn)

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_history)
        top_bar.addWidget(refresh_btn)
        layout.addLayout(top_bar)

        # Search Bar
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Search history by file, pattern, or event type...")
        self.search_edit.textChanged.connect(self.load_history)
        layout.addWidget(self.search_edit)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Timestamp", "Finding / Event", "Category", "File & Line", "Severity", "Lifecycle Status"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 110)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 115)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.verticalHeader().setMinimumSectionSize(36)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)

        self.records: list[dict] = []
        self.load_history()

    def load_history(self):
        query = self.search_edit.text().strip().lower()
        findings = self.bridge.list_findings(limit=500)
        self.records = findings

        filtered = []
        for f in findings:
            f_name = str(f.get("pattern_name", "")).lower()
            f_path = str(f.get("file_path", "")).lower()
            f_cat = str(f.get("category", "")).lower()
            f_st = str(f.get("status", "")).lower()

            if query and not (query in f_name or query in f_path or query in f_cat or query in f_st):
                continue
            filtered.append(f)

        self.table.setRowCount(len(filtered))
        for row_idx, f in enumerate(filtered):
            self.table.setRowHeight(row_idx, 42)

            # Timestamp
            ts = f.get("detected_at", "")[:19].replace("T", " ")
            t_item = QTableWidgetItem(ts)
            t_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 0, t_item)

            # Finding / Event
            name_item = QTableWidgetItem(f.get("pattern_name", "Finding"))
            self.table.setItem(row_idx, 1, name_item)

            # Category
            cat_item = QTableWidgetItem(f.get("category", "Credential").title())
            cat_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 2, cat_item)

            # File & Line
            loc_str = f"{Path(f.get('file_path', '')).name} : L{f.get('line_number', 1)}"
            loc_item = QTableWidgetItem(loc_str)
            loc_item.setForeground(QColor(ACCENT_BLUE))
            self.table.setItem(row_idx, 3, loc_item)

            # Severity
            sev_badge = SeverityBadge(f.get("severity", "medium"))
            s_box = QWidget()
            sl = QHBoxLayout(s_box)
            sl.setContentsMargins(0, 0, 0, 0)
            sl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sl.addWidget(sev_badge)
            self.table.setCellWidget(row_idx, 4, s_box)

            # Status
            st_badge = StatusBadge(f.get("status", "detected"))
            st_box = QWidget()
            stl = QHBoxLayout(st_box)
            stl.setContentsMargins(0, 0, 0, 0)
            stl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            stl.addWidget(st_badge)
            self.table.setCellWidget(row_idx, 5, st_box)

    def export_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export History to CSV", "security_history.csv", "CSV Files (*.csv)")
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Timestamp", "Pattern", "Category", "Severity", "File", "Line", "Status"])
                for r in self.records:
                    writer.writerow([
                        r.get("id"),
                        r.get("detected_at"),
                        r.get("pattern_name"),
                        r.get("category"),
                        r.get("severity"),
                        r.get("file_path"),
                        r.get("line_number"),
                        r.get("status")
                    ])
            QMessageBox.information(self, "Export Successful", f"Saved {len(self.records)} events to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV:\n{e}")
