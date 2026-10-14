"""
PDF Audit Report Generator
Generates executive-grade security audit reports in PDF format using Qt's native QPdfWriter and QTextDocument.
"""

from __future__ import annotations
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtGui import QTextDocument, QPdfWriter, QPageSize
from PySide6.QtCore import QMarginsF


class PDFReportGenerator:
    """Generates PDF audit reports combining scanner, masking and auditor results."""

    @staticmethod
    def generate_report(
        output_path: str,
        project_name: str,
        project_path: str,
        auditor_name: str,
        stats: dict[str, Any],
        secret_findings: list[dict[str, Any]],
        isolated_secrets: list[dict[str, Any]],
        audit_findings: list[Any],
        risk_score: float,
        risk_category: str,
    ) -> str:
        """Renders comprehensive HTML audit document and exports it to PDF."""

        target_path = Path(output_path).expanduser().resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        now_str = datetime.now().strftime("%B %d, %Y - %I:%M %p")

        # Color based on risk category
        score_color = "#10B981"
        if risk_score > 60:
            score_color = "#EF4444"
        elif risk_score > 30:
            score_color = "#F59E0B"

        # Format secret findings rows
        secret_rows_html = ""
        if secret_findings:
            for f in secret_findings[:25]:
                sev = f.get("severity", "MEDIUM").upper()
                sev_color = "#EF4444" if sev == "CRITICAL" else ("#F59E0B" if sev == "HIGH" else "#38BDF8")
                secret_rows_html += f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0;"><span style="background-color: {sev_color}; color: #FFFFFF; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{sev}</span></td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-weight: 600;">{f.get("pattern_name", "Secret")}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-family: monospace; font-size: 11px;">{Path(f.get("file_path", "")).name} : L{f.get("line_number", 1)}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; color: #64748B;">{f.get("category", "Credential")}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0;">{f.get("status", "detected").title()}</td>
                </tr>
                """
        else:
            secret_rows_html = "<tr><td colspan='5' style='padding: 12px; text-align: center; color: #64748B;'>No exposed secrets detected.</td></tr>"

        # Format config audit findings rows
        audit_rows_html = ""
        if audit_findings:
            for af in audit_findings[:25]:
                rule_id = getattr(af, "rule_id", "CFG-???")
                title = getattr(af, "title", "Configuration Risk")
                sev = getattr(af, "severity", "High").upper()
                file_name = Path(getattr(af, "file_path", "")).name
                evidence = getattr(af, "evidence", "")
                recommendation = getattr(af, "recommendation", "")
                sev_color = "#EF4444" if sev in ("CRITICAL", "HIGH") else "#F59E0B"
                audit_rows_html += f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0;"><span style="background-color: {sev_color}; color: #FFFFFF; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">{sev}</span></td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-weight: 600;">{rule_id}: {title}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-family: monospace; font-size: 11px;">{file_name}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-size: 11px; color: #475569;">{recommendation}</td>
                </tr>
                """
        else:
            audit_rows_html = "<tr><td colspan='4' style='padding: 12px; text-align: center; color: #64748B;'>No configuration risks identified.</td></tr>"

        # Format isolated secrets rows
        isolated_rows_html = ""
        if isolated_secrets:
            for iso in isolated_secrets[:15]:
                var_name = iso.get("variable_name", "SECRET")
                placeholder = iso.get("placeholder", "${SECRET}")
                status = iso.get("isolation_status", "masked").title()
                isolated_rows_html += f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-weight: 600;">{var_name}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-family: monospace; color: #2563EB;">{placeholder}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; color: #10B981; font-weight: 600;">AES-256-GCM Encrypted</td>
                    <td style="padding: 8px; border-bottom: 1px solid #E2E8F0;">{status}</td>
                </tr>
                """
        else:
            isolated_rows_html = "<tr><td colspan='4' style='padding: 12px; text-align: center; color: #64748B;'>No secrets currently isolated in vault.</td></tr>"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    color: #1E293B;
                    line-height: 1.5;
                    margin: 0;
                    padding: 0;
                }}
                .header-banner {{
                    background: #0B111E;
                    color: #FFFFFF;
                    padding: 24px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                }}
                .badge {{
                    display: inline-block;
                    padding: 4px 10px;
                    border-radius: 6px;
                    font-size: 11px;
                    font-weight: bold;
                }}
                .stat-box {{
                    background: #F8FAFC;
                    border: 1px solid #E2E8F0;
                    border-radius: 8px;
                    padding: 14px;
                    text-align: center;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 12px;
                    margin-bottom: 24px;
                }}
                th {{
                    background-color: #F1F5F9;
                    color: #475569;
                    font-size: 11px;
                    text-align: left;
                    padding: 8px;
                    border-bottom: 2px solid #CBD5E1;
                    text-transform: uppercase;
                }}
                h2 {{
                    color: #0F172A;
                    font-size: 16px;
                    border-bottom: 2px solid #0084FF;
                    padding-bottom: 6px;
                    margin-top: 24px;
                }}
                .footer {{
                    margin-top: 36px;
                    padding-top: 12px;
                    border-top: 1px solid #CBD5E1;
                    font-size: 11px;
                    color: #64748B;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="header-banner">
                <table style="width: 100%; border: none; margin: 0;">
                    <tr>
                        <td style="border: none;">
                            <h1 style="margin: 0; font-size: 22px; color: #FFFFFF;">SecureGuard Security Audit Report</h1>
                            <p style="margin: 4px 0 0 0; color: #94A3B8; font-size: 13px;">Desktop Security Agent — Automated Assessment Report</p>
                        </td>
                        <td style="border: none; text-align: right;">
                            <span style="background-color: {score_color}; color: #FFFFFF; padding: 6px 14px; border-radius: 8px; font-weight: bold; font-size: 14px;">
                                Risk Score: {risk_score} / 100
                            </span>
                            <div style="color: #94A3B8; font-size: 11px; margin-top: 6px;">Category: {risk_category}</div>
                        </td>
                    </tr>
                </table>
            </div>

            <table style="width: 100%; margin-bottom: 20px;">
                <tr>
                    <td style="width: 50%; padding: 4px 0;"><strong>Project:</strong> {project_name}</td>
                    <td style="width: 50%; padding: 4px 0;"><strong>Generated:</strong> {now_str}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 0;"><strong>Target Path:</strong> <span style="font-family: monospace;">{project_path}</span></td>
                    <td style="padding: 4px 0;"><strong>Auditor:</strong> {auditor_name}</td>
                </tr>
            </table>

            <h2>Executive Summary</h2>
            <table style="width: 100%;">
                <tr>
                    <td style="width: 25%; padding: 6px;">
                        <div class="stat-box">
                            <div style="font-size: 11px; color: #64748B; font-weight: bold;">FILES SCANNED</div>
                            <div style="font-size: 20px; font-weight: bold; color: #0084FF;">{stats.get('files_scanned', 0)}</div>
                        </div>
                    </td>
                    <td style="width: 25%; padding: 6px;">
                        <div class="stat-box">
                            <div style="font-size: 11px; color: #64748B; font-weight: bold;">SECRETS DETECTED</div>
                            <div style="font-size: 20px; font-weight: bold; color: #EF4444;">{stats.get('secrets_detected', 0)}</div>
                        </div>
                    </td>
                    <td style="width: 25%; padding: 6px;">
                        <div class="stat-box">
                            <div style="font-size: 11px; color: #64748B; font-weight: bold;">ISOLATED SECRETS</div>
                            <div style="font-size: 20px; font-weight: bold; color: #10B981;">{stats.get('isolated_secrets', 0)}</div>
                        </div>
                    </td>
                    <td style="width: 25%; padding: 6px;">
                        <div class="stat-box">
                            <div style="font-size: 11px; color: #64748B; font-weight: bold;">CONFIG RISKS</div>
                            <div style="font-size: 20px; font-weight: bold; color: #F59E0B;">{len(audit_findings)}</div>
                        </div>
                    </td>
                </tr>
            </table>

            <h2>Static Configuration Security Risks</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 38%;">Rule & Issue</th>
                        <th style="width: 20%;">File</th>
                        <th style="width: 30%;">Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {audit_rows_html}
                </tbody>
            </table>

            <h2>Exposed Secrets & Credential Detections</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 32%;">Pattern Name</th>
                        <th style="width: 26%;">Location</th>
                        <th style="width: 15%;">Category</th>
                        <th style="width: 15%;">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {secret_rows_html}
                </tbody>
            </table>

            <h2>Secret Isolation Vault Status</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 30%;">Variable Name</th>
                        <th style="width: 30%;">Config Placeholder</th>
                        <th style="width: 25%;">Storage Encryption</th>
                        <th style="width: 15%;">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {isolated_rows_html}
                </tbody>
            </table>

            <div class="footer">
                Report generated by <strong>SecureGuard Desktop Security Agent</strong> — Confidential security document.
            </div>
        </body>
        </html>
        """

        doc = QTextDocument()
        doc.setHtml(html_content)

        writer = QPdfWriter(str(target_path))
        writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        writer.setResolution(150)
        writer.setPageMargins(QMarginsF(12, 12, 12, 12))

        doc.print_(writer)
        return str(target_path)
