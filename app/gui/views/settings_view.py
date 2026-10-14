"""
Settings View
Allows users to configure and customize detection rules and file eligibility rules.
Edits config/pattern_rules.yaml and config/file_rules.yaml with visual rule builder,
regex tester, and live YAML code editor.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import TYPE_CHECKING
import yaml

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QTabWidget, QFrame,
    QMessageBox, QSplitter
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from app.gui.theme import (
    BG_CARD, BG_INPUT, BORDER_COLOR, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_BLUE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW
)

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge


class SettingsView(QWidget):
    """Rule Configuration & Custom Rule Addition Screen."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Header
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("⚙️ Security Agent Configuration")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Customize pattern detection rules (config/pattern_rules.yaml) and file scanning filters (config/file_rules.yaml).")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()

        self.reload_btn = QPushButton("🔄 Reload Pipelines")
        self.reload_btn.setStyleSheet(f"""
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
        self.reload_btn.clicked.connect(self.reload_all_rules)
        top_bar.addWidget(self.reload_btn)
        layout.addLayout(top_bar)

        # Tab Widget for Pattern Rules vs File Rules
        self.tabs = QTabWidget()

        # TAB 1: Pattern Rules Editor
        self.tab_patterns = self.create_pattern_rules_tab()
        self.tabs.addTab(self.tab_patterns, "🔍 Detection Pattern Rules")

        # TAB 2: File Rules Editor
        self.tab_files = self.create_file_rules_tab()
        self.tabs.addTab(self.tab_files, "📁 File Eligibility Rules")

        layout.addWidget(self.tabs)

    # ------------------------------------------------------------------ #
    # TAB 1: Pattern Detection Rules
    # ------------------------------------------------------------------ #

    def create_pattern_rules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Column: Add New Custom Rule Form
        left_card = QFrame()
        left_card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 14px;
            }}
        """)
        left_layout = QVBoxLayout(left_card)
        left_layout.setSpacing(10)

        c_title = QLabel("➕ Add Custom Detection Rule")
        c_title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
        left_layout.addWidget(c_title)

        c_desc = QLabel("Define a custom pattern to detect internal company tokens, specific keys or credentials.")
        c_desc.setWordWrap(True)
        c_desc.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        left_layout.addWidget(c_desc)

        # Form fields
        grid = QGridLayout()
        grid.setSpacing(8)

        grid.addWidget(QLabel("Pattern ID:"), 0, 0)
        self.rule_id_edit = QLineEdit("custom_company_token")
        grid.addWidget(self.rule_id_edit, 0, 1)

        grid.addWidget(QLabel("Rule Name:"), 1, 0)
        self.rule_name_edit = QLineEdit("Internal Company Token")
        grid.addWidget(self.rule_name_edit, 1, 1)

        grid.addWidget(QLabel("Category:"), 2, 0)
        self.rule_cat_combo = QComboBox()
        self.rule_cat_combo.addItems(["api_key", "access_token", "password", "private_key", "secret_key"])
        grid.addWidget(self.rule_cat_combo, 2, 1)

        grid.addWidget(QLabel("Provider:"), 3, 0)
        self.rule_prov_edit = QLineEdit("Custom")
        grid.addWidget(self.rule_prov_edit, 3, 1)

        grid.addWidget(QLabel("Regex:"), 4, 0)
        self.rule_regex_edit = QLineEdit(r"\bcorp_[A-Za-z0-9]{24,32}\b")
        grid.addWidget(self.rule_regex_edit, 4, 1)

        grid.addWidget(QLabel("Severity:"), 5, 0)
        self.rule_sev_combo = QComboBox()
        self.rule_sev_combo.addItems(["critical", "high", "medium", "low"])
        self.rule_sev_combo.setCurrentText("high")
        grid.addWidget(self.rule_sev_combo, 5, 1)

        grid.addWidget(QLabel("Confidence:"), 6, 0)
        self.rule_conf_edit = QLineEdit("0.98")
        grid.addWidget(self.rule_conf_edit, 6, 1)

        grid.addWidget(QLabel("Description:"), 7, 0)
        self.rule_desc_edit = QLineEdit("Detects internal company authorization tokens.")
        grid.addWidget(self.rule_desc_edit, 7, 1)

        left_layout.addLayout(grid)

        # Regex Test Box
        test_box = QFrame()
        test_box.setStyleSheet(f"background-color: #101726; border: 1px solid {BORDER_COLOR}; border-radius: 8px; padding: 8px;")
        tb_layout = QVBoxLayout(test_box)
        tb_layout.setSpacing(6)

        test_header = QHBoxLayout()
        test_header.addWidget(QLabel("Regex Tester:"))
        test_header.addStretch()
        self.test_result_lbl = QLabel("Ready")
        self.test_result_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        test_header.addWidget(self.test_result_lbl)
        tb_layout.addLayout(test_header)

        self.test_sample_edit = QLineEdit("corp_982b6c1fa789c0de12345678")
        self.test_sample_edit.setPlaceholderText("Paste sample string here to test regex...")
        tb_layout.addWidget(self.test_sample_edit)

        test_btn = QPushButton("Test Regex Match")
        test_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1E2E4A;
                color: #FFFFFF;
                border: 1px solid #3B527E;
                border-radius: 6px;
                padding: 7px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: #2A3F66;
                border-color: {ACCENT_BLUE};
            }}
        """)
        test_btn.clicked.connect(self.test_regex_pattern)
        tb_layout.addWidget(test_btn)

        left_layout.addWidget(test_box)

        # Add Button
        add_btn = QPushButton("➕ Add Rule to pattern_rules.yaml")
        add_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_BLUE};
                color: #FFFFFF;
                border: 1px solid #38BDF8;
                border-radius: 8px;
                font-weight: 700;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #006ED3;
                border-color: #60A5FA;
            }}
        """)
        add_btn.clicked.connect(self.add_custom_rule)
        left_layout.addWidget(add_btn)

        splitter.addWidget(left_card)

        # Right Column: Raw pattern_rules.yaml Editor
        right_card = QFrame()
        right_card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 14px;
            }}
        """)
        right_layout = QVBoxLayout(right_card)
        right_layout.setSpacing(10)

        r_header = QHBoxLayout()
        r_title = QLabel("📄 config/pattern_rules.yaml (Direct Editor)")
        r_title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
        r_header.addWidget(r_title)
        r_header.addStretch()

        save_patterns_btn = QPushButton("💾 Save YAML & Reload")
        save_patterns_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #064E3B;
                color: #34D399;
                border: 1px solid #10B98155;
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: #10B981;
                color: #FFFFFF;
            }}
        """)
        save_patterns_btn.clicked.connect(self.save_patterns_yaml)
        r_header.addWidget(save_patterns_btn)
        right_layout.addLayout(r_header)

        self.patterns_text_edit = QPlainTextEdit()
        self.patterns_text_edit.setFont(QFont("Consolas", 10))
        self.patterns_text_edit.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {BG_INPUT};
                color: #E2E8F0;
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
            }}
        """)
        right_layout.addWidget(self.patterns_text_edit)

        splitter.addWidget(right_card)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)

        layout.addWidget(splitter)

        self.load_pattern_rules()
        return widget

    def test_regex_pattern(self):
        pat_str = self.rule_regex_edit.text().strip()
        sample = self.test_sample_edit.text()

        try:
            compiled = re.compile(pat_str)
            m = compiled.search(sample)
            if m:
                self.test_result_lbl.setText(f"✅ Match Found: '{m.group(0)}'")
                self.test_result_lbl.setStyleSheet(f"color: {COLOR_GREEN}; font-weight: bold; font-size: 11px;")
            else:
                self.test_result_lbl.setText("❌ No Match")
                self.test_result_lbl.setStyleSheet(f"color: {COLOR_RED}; font-weight: bold; font-size: 11px;")
        except Exception as e:
            self.test_result_lbl.setText(f"⚠️ Invalid Regex: {e}")
            self.test_result_lbl.setStyleSheet(f"color: {COLOR_YELLOW}; font-size: 11px;")

    def add_custom_rule(self):
        rule_id = self.rule_id_edit.text().strip()
        name = self.rule_name_edit.text().strip()
        cat = self.rule_cat_combo.currentText()
        prov = self.rule_prov_edit.text().strip()
        reg = self.rule_regex_edit.text().strip()
        sev = self.rule_sev_combo.currentText()
        try:
            conf = float(self.rule_conf_edit.text().strip())
        except ValueError:
            conf = 0.95
        desc = self.rule_desc_edit.text().strip()

        if not rule_id or not reg:
            QMessageBox.warning(self, "Validation Error", "Pattern ID and Regular Expression are required.")
            return

        # Load existing YAML
        raw = self.bridge.read_pattern_rules_yaml()
        try:
            data = yaml.safe_load(raw) or {}
            rules_list = data.get("rules", [])
            if not isinstance(rules_list, list):
                rules_list = []

            # Check duplicate ID
            for r in rules_list:
                if isinstance(r, dict) and r.get("pattern_id") == rule_id:
                    QMessageBox.warning(self, "Duplicate Rule ID", f"A rule with ID '{rule_id}' already exists.")
                    return

            new_rule = {
                "pattern_id": rule_id,
                "name": name,
                "category": cat,
                "provider": prov,
                "regex": reg,
                "severity": sev,
                "base_confidence": conf,
                "entropy_required": False,
                "context_required": False,
                "enabled": True,
                "description": desc,
            }
            rules_list.append(new_rule)
            data["rules"] = rules_list

            updated_yaml = yaml.dump(data, sort_keys=False, default_flow_style=False)
            self.bridge.save_pattern_rules_yaml(updated_yaml)
            self.patterns_text_edit.setPlainText(updated_yaml)

            QMessageBox.information(
                self,
                "Rule Added",
                f"Custom rule '{rule_id}' was successfully added to pattern_rules.yaml!\n"
                "The live detection engine has been reloaded."
            )
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not update pattern rules:\n{e}")

    def load_pattern_rules(self):
        content = self.bridge.read_pattern_rules_yaml()
        self.patterns_text_edit.setPlainText(content)

    def save_patterns_yaml(self):
        text = self.patterns_text_edit.toPlainText()
        try:
            self.bridge.save_pattern_rules_yaml(text)
            QMessageBox.information(self, "Saved", "pattern_rules.yaml saved successfully and engine reloaded!")
        except Exception as e:
            QMessageBox.critical(self, "YAML Error", f"Invalid YAML format:\n{e}")

    # ------------------------------------------------------------------ #
    # TAB 2: File Eligibility Rules
    # ------------------------------------------------------------------ #

    def create_file_rules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER_COLOR};
                border-radius: 10px;
                padding: 16px;
            }}
        """)
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel("📄 config/file_rules.yaml (Direct File Filter Editor)")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()

        save_btn = QPushButton("💾 Save File Rules & Apply")
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #064E3B;
                color: #34D399;
                border: 1px solid #10B981;
                border-radius: 6px;
                padding: 7px 16px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: #10B981;
                color: #FFFFFF;
            }}
        """)
        save_btn.clicked.connect(self.save_file_rules_yaml)
        header.addWidget(save_btn)
        c_layout.addLayout(header)

        desc = QLabel(
            "Configure eligible filenames (.env, Dockerfile), extensions (.json, .yaml, .yml), "
            "name patterns (settings, config), and excluded directories (.git, node_modules, venv)."
        )
        desc.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        c_layout.addWidget(desc)

        self.file_rules_text_edit = QPlainTextEdit()
        self.file_rules_text_edit.setFont(QFont("Consolas", 10))
        self.file_rules_text_edit.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {BG_INPUT};
                color: #E2E8F0;
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
            }}
        """)
        c_layout.addWidget(self.file_rules_text_edit)

        layout.addWidget(card)

        self.load_file_rules()
        return widget

    def load_file_rules(self):
        content = self.bridge.read_file_rules_yaml()
        self.file_rules_text_edit.setPlainText(content)

    def save_file_rules_yaml(self):
        text = self.file_rules_text_edit.toPlainText()
        try:
            self.bridge.save_file_rules_yaml(text)
            QMessageBox.information(self, "Saved", "file_rules.yaml saved and file filter reloaded successfully!")
        except Exception as e:
            QMessageBox.critical(self, "YAML Error", f"Invalid YAML syntax:\n{e}")

    def reload_all_rules(self):
        try:
            self.bridge.reload_rules()
            self.load_pattern_rules()
            self.load_file_rules()
            QMessageBox.information(self, "Reloaded", "All detection and file filtering rules reloaded into memory.")
        except Exception as e:
            QMessageBox.critical(self, "Reload Error", f"Failed to reload rules:\n{e}")
