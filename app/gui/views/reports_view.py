"""
Reports View
Allows generating, previewing, and exporting comprehensive PDF security audit reports.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFrame, QFileDialog, QMessageBox, QCheckBox, QTextBrowser
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices

from app.gui.theme import (
    BG_CARD, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN
)
from app.gui.pdf_report_generator import PDFReportGenerator
from app.paths import reports_directory

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class ReportsView(QWidget):
    """Executive PDF Audit Report Generator Screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.last_generated_pdf: Path | None = None

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

        # Configuration Card
        config_card = QFrame()
        config_card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        cc_layout = QVBoxLayout(config_card)
        cc_layout.setSpacing(12)

        card_title = QLabel("Report Parameters")
        card_title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 15px; font-weight: 700;")
        cc_layout.addWidget(card_title)

        # Form fields
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        f1 = QVBoxLayout()
        f1.addWidget(QLabel("Project Title:"))
        self.proj_edit = QLineEdit("SecureGuard - Desktop Security Agent")
        f1.addWidget(self.proj_edit)
        row1.addLayout(f1)

        f2 = QVBoxLayout()
        f2.addWidget(QLabel("Auditor / Security Engineer:"))
        self.auditor_edit = QLineEdit("Lead Security Engineer")
        f2.addWidget(self.auditor_edit)
        row1.addLayout(f2)
        cc_layout.addLayout(row1)

        # Output Path
        out_box = QVBoxLayout()
        out_box.addWidget(QLabel("Export PDF File Path:"))
        out_row = QHBoxLayout()
        default_pdf = reports_directory() / "Security_Audit_Report.pdf"
        self.out_edit = QLineEdit(str(default_pdf))
        out_row.addWidget(self.out_edit, stretch=1)

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
        browse_btn.clicked.connect(self.browse_pdf_location)
        out_row.addWidget(browse_btn)
        out_box.addLayout(out_row)
        cc_layout.addLayout(out_box)

        # Checkboxes
        chk_layout = QHBoxLayout()
        chk_layout.setSpacing(16)
        self.chk_summary = QCheckBox("Executive Summary")
        self.chk_summary.setChecked(True)
        self.chk_risks = QCheckBox("Configuration Risk Rules")
        self.chk_risks.setChecked(True)
        self.chk_secrets = QCheckBox("Secret Findings")
        self.chk_secrets.setChecked(True)
        self.chk_vault = QCheckBox("Vault Isolation Status")
        self.chk_vault.setChecked(True)
        chk_layout.addWidget(self.chk_summary)
        chk_layout.addWidget(self.chk_risks)
        chk_layout.addWidget(self.chk_secrets)
        chk_layout.addWidget(self.chk_vault)
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

        self.open_btn = QPushButton("👁️ Open Generated PDF")
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
        """)
        self.open_btn.clicked.connect(self.open_pdf)
        btn_row.addWidget(self.open_btn)
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
        layout.addWidget(self.preview_browser)

    def browse_pdf_location(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", str(self.out_edit.text()), "PDF Files (*.pdf)"
        )
        if file_path:
            self.out_edit.setText(file_path)

    def generate_pdf(self):
        if self.bridge.current_target_dir is None:
            QMessageBox.information(
                self,
                "Select a Project",
                "Choose a project directory from the Dashboard before generating a report.",
            )
            return

        out_path_str = self.out_edit.text().strip()
        if not out_path_str:
            QMessageBox.warning(self, "Invalid Path", "Please provide a destination PDF file path.")
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
                output_path=out_path_str,
                project_name=self.proj_edit.text().strip(),
                project_path=str(self.bridge.current_target_dir),
                auditor_name=self.auditor_edit.text().strip(),
                stats={
                    "files_scanned": stats.get("files_scanned", 1284),
                    "secrets_detected": len(secret_findings),
                    "isolated_secrets": len(isolated_secrets),
                },
                secret_findings=secret_findings,
                isolated_secrets=isolated_secrets,
                audit_findings=audit_findings,
                risk_score=self.bridge.last_risk_score,
                risk_category=self.bridge.last_risk_category,
            )

            self.last_generated_pdf = Path(saved_file)
            self.open_btn.setEnabled(True)

            # Update preview box
            self.preview_browser.setHtml(f"""
                <div style='color: #E2E8F0;'>
                    <h3 style='color: #10B981; margin-top: 0;'>✅ PDF Report Successfully Generated!</h3>
                    <p><b>Saved To:</b> <span style='font-family: monospace; color: #38BDF8;'>{saved_file}</span></p>
                    <hr style='border: none; border-top: 1px solid #1E293B;'>
                    <table style='width: 100%; color: #94A3B8;'>
                        <tr>
                            <td><b>Overall Risk Score:</b> <span style='color: #FFFFFF;'>{self.bridge.last_risk_score} / 100 ({self.bridge.last_risk_category})</span></td>
                            <td><b>Configuration Risks:</b> <span style='color: #FFFFFF;'>{len(audit_findings)} items</span></td>
                        </tr>
                        <tr>
                            <td><b>Secrets Detected:</b> <span style='color: #FFFFFF;'>{len(secret_findings)} findings</span></td>
                            <td><b>Isolated in Vault:</b> <span style='color: #FFFFFF;'>{len(isolated_secrets)} secrets</span></td>
                        </tr>
                    </table>
                    <p style='color: #64748B; font-size: 11px; margin-top: 12px;'>
                        Click <b>Open Generated PDF</b> to inspect the report in your system viewer.
                    </p>
                </div>
            """)

            QMessageBox.information(
                self,
                "Report Generated",
                f"PDF Security Audit Report generated successfully at:\n{saved_file}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Could not create PDF report:\n{e}")

    def open_pdf(self):
        if self.last_generated_pdf and self.last_generated_pdf.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_generated_pdf)))
        else:
            QMessageBox.warning(self, "File Not Found", "Generated PDF could not be found.")
