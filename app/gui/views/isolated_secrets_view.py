"""
Isolated Secrets View
Displays the AES-256-GCM encrypted secret vault (Component 2).
Provides secret rollback and authorized decryption verification.
"""

from __future__ import annotations
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    COLOR_GREEN, COLOR_RED, COLOR_YELLOW, ACCENT_BLUE
)
from app.gui.components.badge import StatusBadge

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class IsolatedSecretsView(QWidget):
    """Component 2 Encrypted Vault Management Screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Header Banner
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("🔐 Encrypted Secret Vault")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Component 2: AES-256-GCM authenticated secret isolation with rollback support.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        header.addLayout(title_box)
        header.addStretch()

        self.refresh_btn = QPushButton("🔄 Refresh Vault")
        self.refresh_btn.setStyleSheet(f"""
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
        self.refresh_btn.clicked.connect(self.load_vault)
        header.addWidget(self.refresh_btn)
        layout.addLayout(header)

        # Vault Security Info Banner
        info_banner = QFrame()
        info_banner.setStyleSheet(f"""
            QFrame {{
                background-color: #0A2540;
                border: 1px solid #0084FF44;
                border-radius: 10px;
                padding: 12px 16px;
            }}
        """)
        ib_layout = QHBoxLayout(info_banner)
        ib_layout.setSpacing(14)

        shield_icon = QLabel("🛡️")
        shield_icon.setStyleSheet("font-size: 20px;")
        ib_layout.addWidget(shield_icon)

        banner_text = QLabel(
            "<b>Zero Plaintext Leakage Policy:</b> Secrets stored in this vault are encrypted with a 256-bit "
            "master key in Windows Credential Manager. Raw secret plaintext is never stored in SQLite or log files."
        )
        banner_text.setWordWrap(True)
        banner_text.setStyleSheet(f"color: #E2E8F0; font-size: 12px;")
        ib_layout.addWidget(banner_text, stretch=1)
        layout.addWidget(info_banner)

        # Secrets Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "ID", "Variable Name", "Placeholder", "File Location", "Ciphertext Token", "Status", "Isolated At", "Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 115)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(7, 180)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.verticalHeader().setMinimumSectionSize(38)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)

        self.load_vault()

    def load_vault(self):
        records = self.bridge.list_isolated_secrets()
        self.table.setRowCount(len(records))

        for row_idx, item in enumerate(records):
            self.table.setRowHeight(row_idx, 44)
            iso_id = item["id"]

            # ID
            id_item = QTableWidgetItem(f"#{iso_id}")
            id_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 0, id_item)

            # Variable Name
            var_item = QTableWidgetItem(item.get("variable_name", ""))
            var_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table.setItem(row_idx, 1, var_item)

            # Placeholder
            ph_item = QTableWidgetItem(item.get("placeholder", ""))
            ph_item.setForeground(QColor(COLOR_GREEN))
            self.table.setItem(row_idx, 2, ph_item)

            # File & Line
            file_name = Path(item.get("file_path", "")).name or "config"
            line_no = item.get("line_number", 1)
            loc_item = QTableWidgetItem(f"{file_name} : L{line_no}")
            self.table.setItem(row_idx, 3, loc_item)

            # Ciphertext preview (Truncated safe token)
            enc_val = item.get("encrypted_value", "")
            preview_token = f"{enc_val[:16]}...{enc_val[-8:]}" if len(enc_val) > 24 else enc_val
            token_item = QTableWidgetItem(preview_token)
            token_item.setFont(QFont("Consolas", 8))
            token_item.setForeground(QColor("#64748B"))
            self.table.setItem(row_idx, 4, token_item)

            # Status
            st = item.get("isolation_status", "masked")
            badge = StatusBadge(st)
            b_box = QWidget()
            bl = QHBoxLayout(b_box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bl.addWidget(badge)
            self.table.setCellWidget(row_idx, 5, b_box)

            # Date
            iso_at = item.get("isolated_at", "")
            date_str = iso_at[:16].replace("T", " ") if iso_at else ""
            date_item = QTableWidgetItem(date_str)
            date_item.setForeground(QColor(TEXT_MUTED))
            self.table.setItem(row_idx, 6, date_item)

            # Actions Box
            act_box = QWidget()
            al = QHBoxLayout(act_box)
            al.setContentsMargins(0, 0, 0, 0)
            al.setAlignment(Qt.AlignmentFlag.AlignCenter)
            al.setSpacing(6)

            if st == "masked":
                rb_btn = QPushButton("Rollback")
                rb_btn.setFixedHeight(28)
                rb_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                rb_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: #78350F;
                        color: #FBBF24;
                        border: 1px solid #F59E0B;
                        border-radius: 6px;
                        padding: 3px 12px;
                        font-size: 11px;
                        font-weight: 700;
                    }}
                    QPushButton:hover {{
                        background-color: #F59E0B;
                        color: #000000;
                    }}
                """)
                rb_btn.clicked.connect(lambda _, i_id=iso_id: self.handle_rollback(i_id))
                al.addWidget(rb_btn)

            dec_btn = QPushButton("Inspect")
            dec_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #24334C;
                    color: #E2E8F0;
                    border: 1px solid #3B527E;
                    border-radius: 6px;
                    padding: 4px 10px;
                    font-size: 11px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: #334566;
                    color: #FFFFFF;
                }}
            """)
            dec_btn.clicked.connect(lambda _, i_id=iso_id: self.handle_inspect(i_id))
            al.addWidget(dec_btn)

            self.table.setCellWidget(row_idx, 7, act_box)

    def handle_rollback(self, isolation_id: int):
        confirm = QMessageBox.question(
            self,
            "Confirm Rollback",
            f"Are you sure you want to rollback isolated secret #{isolation_id}?\n\n"
            "This will restore the original file from the AES-256 encrypted backup.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                self.bridge.rollback_isolation(isolation_id)
                QMessageBox.information(self, "Rollback Complete", "Secret restored to original file successfully.")
                self.load_vault()
            except Exception as e:
                QMessageBox.critical(self, "Rollback Failed", f"Could not rollback secret:\n{e}")

    def handle_inspect(self, isolation_id: int):
        confirm = QMessageBox.warning(
            self,
            "Authorized Secret Decryption",
            "This action decrypts the secret in memory for verification.\n"
            "An audit log entry will be created. Proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                plaintext = self.bridge.decrypt_secret_authorized(isolation_id)
                masked_preview = plaintext[:2] + ("*" * (len(plaintext) - 4)) + plaintext[-2:] if len(plaintext) > 4 else "****"
                QMessageBox.information(
                    self,
                    "Decryption Verified",
                    f"Vault Integrity: Verified OK\n\n"
                    f"Decrypted Secret Length: {len(plaintext)} characters\n"
                    f"Masked Preview: {masked_preview}\n\n"
                    f"Status: Authenticated AES-256-GCM decryption succeeded."
                )
            except Exception as e:
                QMessageBox.critical(self, "Decryption Failed", f"Unable to decrypt secret:\n{e}")
