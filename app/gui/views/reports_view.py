"""
Reports View
Allows generating, previewing, and exporting comprehensive PDF security audit reports.

Reports are saved to the user's Downloads folder by default; the folder and the
file name can both be changed before generating.
"""

from __future__ import annotations
import html
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFrame, QFileDialog, QMessageBox, QCheckBox, QTextBrowser
)
from PySide6.QtCore import Qt, QUrl, QStandardPaths
from PySide6.QtGui import QDesktopServices

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE
)
from app.gui.pdf_report_generator import PDFReportGenerator
from app.paths import build_report_path, default_report_filename, downloads_directory

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


def default_output_directory() -> Path:
    """The user's Downloads folder (as reported by the OS, e.g. when it is redirected)."""
    location = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
    if location and Path(location).is_dir():
        return Path(location)
    return downloads_directory()


_SECONDARY_BTN = f"""
QPushButton {{
    background-color: #1E2E4A; color: #FFFFFF; border: 1px solid #3B527E;
    border-radius: 8px; padding: 8px 16px; font-weight: 700;
}}
QPushButton:hover {{ background-color: #2A3F66; border-color: {ACCENT_BLUE}; }}
QPushButton:disabled {{ color: #64748B; background-color: #131B2E; border-color: #1E2B45; }}
"""

_FIELD_LABEL = f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600;"


class ReportsView(QWidget):
    """Executive PDF Audit Report Generator Screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.last_generated_pdf: Path | None = None
        self._auto_filename = True  # until the user types their own name

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(18)

        # Header
        title_box = QVBoxLayout()
        title = QLabel("📑 Security Audit PDF Reports")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Generate printable, executive-ready PDF audit reports covering scanner, vault, and configuration risks.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        layout.addLayout(title_box)

        # Configuration Card (scoped by object name so the border/padding does not
        # leak onto the labels inside it)
        config_card = QFrame()
        config_card.setObjectName("reportCard")
        config_card.setStyleSheet(f"""
            QFrame#reportCard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
            }}
            QFrame#reportCard QLabel {{ background: transparent; border: none; padding: 0px; }}
        """)
        cc_layout = QVBoxLayout(config_card)
        cc_layout.setContentsMargins(20, 18, 20, 18)
        cc_layout.setSpacing(12)

        card_title = QLabel("Report Parameters")
        card_title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        cc_layout.addWidget(card_title)

        # Project / auditor
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        f1 = QVBoxLayout()
        f1.setSpacing(4)
        f1.addWidget(self._field_label("Project Title"))
        self.proj_edit = QLineEdit("SecureGuard - Desktop Security Agent")
        f1.addWidget(self.proj_edit)
        row1.addLayout(f1)

        f2 = QVBoxLayout()
        f2.setSpacing(4)
        f2.addWidget(self._field_label("Auditor / Security Engineer"))
        self.auditor_edit = QLineEdit("Lead Security Engineer")
        f2.addWidget(self.auditor_edit)
        row1.addLayout(f2)
        cc_layout.addLayout(row1)

        # Destination folder (defaults to Downloads) + file name
        folder_box = QVBoxLayout()
        folder_box.setSpacing(4)
        folder_box.addWidget(self._field_label("Save to folder"))
        folder_row = QHBoxLayout()
        self.folder_edit = QLineEdit(str(default_output_directory()))
        self.folder_edit.setPlaceholderText("Choose where the PDF should be saved")
        folder_row.addWidget(self.folder_edit, stretch=1)

        browse_btn = QPushButton("📁 Browse...")
        browse_btn.setStyleSheet(_SECONDARY_BTN)
        browse_btn.clicked.connect(self.browse_folder)
        folder_row.addWidget(browse_btn)

        downloads_btn = QPushButton("⬇ Downloads")
        downloads_btn.setToolTip("Reset the destination to your Downloads folder")
        downloads_btn.setStyleSheet(_SECONDARY_BTN)
        downloads_btn.clicked.connect(lambda: self.folder_edit.setText(str(default_output_directory())))
        folder_row.addWidget(downloads_btn)
        folder_box.addLayout(folder_row)
        cc_layout.addLayout(folder_box)

        name_box = QVBoxLayout()
        name_box.setSpacing(4)
        name_box.addWidget(self._field_label("File name"))
        self.name_edit = QLineEdit(default_report_filename())
        self.name_edit.textEdited.connect(self._on_filename_edited)
        name_box.addWidget(self.name_edit)
        cc_layout.addLayout(name_box)

        for edit in (self.proj_edit, self.auditor_edit, self.folder_edit, self.name_edit):
            edit.setMinimumHeight(38)

        # Sections to include
        sections_lbl = self._field_label("Include in report")
        cc_layout.addWidget(sections_lbl)
        chk_layout = QHBoxLayout()
        chk_layout.setSpacing(16)
        self.chk_summary = QCheckBox("Executive Summary")
        self.chk_risks = QCheckBox("Configuration Risk Rules")
        self.chk_secrets = QCheckBox("Secret Findings")
        self.chk_vault = QCheckBox("Vault Isolation Status")
        for chk in (self.chk_summary, self.chk_risks, self.chk_secrets, self.chk_vault):
            chk.setChecked(True)
            chk_layout.addWidget(chk)
        chk_layout.addStretch()
        cc_layout.addLayout(chk_layout)

        # Action Buttons
        btn_row = QHBoxLayout()
        self.gen_btn = QPushButton("📄 Generate PDF Audit Report")
        self.gen_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                font-weight: 700;
                padding: 10px 24px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: #0070D8;
            }}
        """)
        self.gen_btn.clicked.connect(self.generate_pdf)
        btn_row.addWidget(self.gen_btn)

        self.open_btn = QPushButton("👁️ Open PDF")
        self.open_btn.setEnabled(False)
        self.open_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #064E3B;
                color: #34D399;
                border: 1px solid #10B98166;
                border-radius: 8px;
                font-weight: 700;
                padding: 10px 20px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: #10B981;
                color: #FFFFFF;
            }}
            QPushButton:disabled {{
                color: #64748B; background-color: #131B2E; border-color: #1E2B45;
            }}
        """)
        self.open_btn.clicked.connect(self.open_pdf)
        btn_row.addWidget(self.open_btn)

        self.folder_btn = QPushButton("📂 Show in Folder")
        self.folder_btn.setEnabled(False)
        self.folder_btn.setStyleSheet(_SECONDARY_BTN)
        self.folder_btn.clicked.connect(self.open_containing_folder)
        btn_row.addWidget(self.folder_btn)
        btn_row.addStretch()
        cc_layout.addLayout(btn_row)

        layout.addWidget(config_card)

        # Status & Preview Browser
        self.preview_browser = QTextBrowser()
        self.preview_browser.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 16px;
                color: {TEXT_SECONDARY};
                font-size: 12px;
            }}
        """)
        self.preview_browser.setHtml(
            "<div style='text-align: center; color: #64748B; padding: 40px;'>"
            "Click <b>Generate PDF Audit Report</b> above to compile findings from all 3 components into an executive PDF."
            "</div>"
        )
        layout.addWidget(self.preview_browser, stretch=1)

    # ------------------------------------------------------------------ #

    @staticmethod
    def _field_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(_FIELD_LABEL)
        return lbl

    def _on_filename_edited(self, _text: str) -> None:
        self._auto_filename = False

    def browse_folder(self) -> None:
        start = self.folder_edit.text().strip()
        if not start or not Path(start).expanduser().is_dir():
            start = str(default_output_directory())
        folder = QFileDialog.getExistingDirectory(self, "Choose Folder to Save the Report", start)
        if folder:
            self.folder_edit.setText(folder)

    def generate_pdf(self):
        try:
            out_path = build_report_path(self.folder_edit.text(), self.name_edit.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Destination", str(exc))
            return

        if out_path.exists():
            answer = QMessageBox.question(
                self, "Replace File?",
                f"'{out_path.name}' already exists in this folder.\nDo you want to replace it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        try:
            # 1. Gather all data from backend
            stats = self.bridge.get_dashboard_data()
            secret_findings = self.bridge.list_findings(limit=100)
            isolated_secrets = self.bridge.list_isolated_secrets()
            audit_findings = self.bridge.last_audit_findings

            # If no audit was run yet, run one on current target directory
            if not audit_findings:
                audit_res = self.bridge.run_project_audit(self.bridge.current_target_dir)
                audit_findings = audit_res.get("findings", [])

            # 2. Generate PDF
            saved_file = PDFReportGenerator.generate_report(
                output_path=str(out_path),
                project_name=self.proj_edit.text().strip(),
                project_path=str(self.bridge.current_target_dir),
                auditor_name=self.auditor_edit.text().strip(),
                stats={
                    "files_scanned": stats.get("files_scanned", 0),
                    "secrets_detected": len(secret_findings),
                    "isolated_secrets": len(isolated_secrets),
                },
                secret_findings=secret_findings,
                isolated_secrets=isolated_secrets,
                audit_findings=audit_findings,
                risk_score=self.bridge.last_risk_score,
                risk_category=self.bridge.last_risk_category,
                include_summary=self.chk_summary.isChecked(),
                include_config_risks=self.chk_risks.isChecked(),
                include_secrets=self.chk_secrets.isChecked(),
                include_vault=self.chk_vault.isChecked(),
            )
        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Could not create PDF report:\n{e}")
            return

        self.last_generated_pdf = Path(saved_file)
        self.open_btn.setEnabled(True)
        self.folder_btn.setEnabled(True)

        # Next report gets a fresh name instead of overwriting this one
        # (only when the user has not typed a custom file name).
        if self._auto_filename:
            self.name_edit.setText(default_report_filename())

        safe_path = html.escape(str(saved_file))
        self.preview_browser.setHtml(f"""
            <div style='color: #E2E8F0;'>
                <h3 style='color: #10B981; margin-top: 0;'>✅ PDF Report Successfully Generated!</h3>
                <p><b>Saved To:</b> <span style='font-family: monospace; color: #38BDF8;'>{safe_path}</span></p>
                <hr style='border: none; border-top: 1px solid #1E293B;'>
                <table style='width: 100%; color: #94A3B8;'>
                    <tr>
                        <td><b>Overall Risk Score:</b> <span style='color: #FFFFFF;'>{self.bridge.last_risk_score} / 100 ({html.escape(str(self.bridge.last_risk_category))})</span></td>
                        <td><b>Configuration Risks:</b> <span style='color: #FFFFFF;'>{len(audit_findings)} items</span></td>
                    </tr>
                    <tr>
                        <td><b>Secrets Detected:</b> <span style='color: #FFFFFF;'>{len(secret_findings)} findings</span></td>
                        <td><b>Isolated in Vault:</b> <span style='color: #FFFFFF;'>{len(isolated_secrets)} secrets</span></td>
                    </tr>
                </table>
                <p style='color: #64748B; font-size: 11px; margin-top: 12px;'>
                    Use <b>Open PDF</b> to view the report or <b>Show in Folder</b> to find the file.
                </p>
            </div>
        """)

    def open_pdf(self):
        if self.last_generated_pdf and self.last_generated_pdf.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_generated_pdf)))
        else:
            QMessageBox.warning(self, "File Not Found", "Generated PDF could not be found. It may have been moved or deleted.")

    def open_containing_folder(self):
        if self.last_generated_pdf and self.last_generated_pdf.parent.is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_generated_pdf.parent)))
        else:
            QMessageBox.warning(self, "Folder Not Found", "The report folder could not be found.")
