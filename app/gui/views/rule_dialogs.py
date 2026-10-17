"""
Popup forms used by the Settings view:

* PatternRuleDialog - add / edit one detection pattern rule
* ValueDialog       - add / edit one entry of a file-eligibility list
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDoubleSpinBox, QFormLayout, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout,
)

from app.gui.theme import (
    ACCENT_BLUE, BG_CARD, BG_INPUT, BG_MAIN, BORDER_COLOR, COLOR_GREEN, COLOR_RED,
    COLOR_YELLOW, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
)
from config.rule_loader import RuleConfigurationError
from config.rule_store import CATEGORIES, SEVERITIES, RuleStore

_DIALOG_STYLE = f"""
QDialog {{ background-color: {BG_MAIN}; }}
QLabel {{ background: transparent; }}
"""

_PRIMARY_BTN = f"""
QPushButton {{
    background-color: {ACCENT_BLUE}; color: #FFFFFF; border: 1px solid #38BDF8;
    border-radius: 8px; padding: 8px 20px; font-weight: 700;
}}
QPushButton:hover {{ background-color: #006ED3; border-color: #60A5FA; }}
"""


def _label(text: str, muted: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {TEXT_MUTED if muted else TEXT_SECONDARY}; font-size: {11 if muted else 12}px;"
    )
    lbl.setWordWrap(muted)
    return lbl


class PatternRuleDialog(QDialog):
    """Popup form to add a new detection rule or edit an existing one."""

    def __init__(self, parent=None, rule: Optional[dict] = None):
        super().__init__(parent)
        self._editing = rule is not None
        self._source = (rule or {}).get("source", "custom")
        self._result: Optional[dict] = None

        self.setModal(True)
        self.setMinimumWidth(560)
        self.setStyleSheet(_DIALOG_STYLE)
        self.setWindowTitle("Edit Detection Rule" if self._editing else "Add Detection Rule")

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(12)

        title = QLabel(self.windowTitle())
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 17px; font-weight: 700;")
        root.addWidget(title)

        if self._editing and self._source != "custom":
            root.addWidget(_label(
                "Built-in rule: your changes are saved as overrides. "
                "Use Reset in the rules list to restore the defaults.", muted=True))
        else:
            root.addWidget(_label(
                "Define a pattern that detects internal tokens, keys or credentials.", muted=True))

        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.id_edit = QLineEdit()
        self.id_edit.setPlaceholderText("e.g. corp_api_token")
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. Corporate API Token")

        self.category_combo = QComboBox()
        self.category_combo.addItems(CATEGORIES)
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(SEVERITIES)
        self.severity_combo.setCurrentText("high")

        self.provider_edit = QLineEdit()
        self.provider_edit.setPlaceholderText("Optional, e.g. AWS")

        self.confidence_spin = QDoubleSpinBox()
        self.confidence_spin.setRange(0.0, 1.0)
        self.confidence_spin.setSingleStep(0.01)
        self.confidence_spin.setDecimals(2)
        self.confidence_spin.setValue(0.90)

        self.regex_edit = QLineEdit()
        self.regex_edit.setFont(QFont("Consolas", 10))
        self.regex_edit.setPlaceholderText(r"e.g. \bcorp_[A-Za-z0-9]{24,32}\b")

        self.desc_edit = QPlainTextEdit()
        self.desc_edit.setFixedHeight(64)
        self.desc_edit.setPlaceholderText("What does this rule detect?")

        form.addRow(_label("Pattern ID *"), self.id_edit)
        form.addRow(_label("Rule name *"), self.name_edit)
        form.addRow(_label("Category *"), self.category_combo)
        form.addRow(_label("Severity *"), self.severity_combo)
        form.addRow(_label("Provider"), self.provider_edit)
        form.addRow(_label("Confidence *"), self.confidence_spin)
        form.addRow(_label("Regex *"), self.regex_edit)
        form.addRow(_label("Description"), self.desc_edit)
        root.addLayout(form)

        opts = QHBoxLayout()
        self.enabled_chk = QCheckBox("Enabled")
        self.enabled_chk.setChecked(True)
        self.entropy_chk = QCheckBox("Require entropy analysis")
        self.context_chk = QCheckBox("Require context analysis")
        for chk in (self.enabled_chk, self.entropy_chk, self.context_chk):
            opts.addWidget(chk)
        opts.addStretch()
        root.addLayout(opts)

        # Regex tester
        tester = QFrame()
        tester.setStyleSheet(
            f"QFrame {{ background-color: {BG_CARD}; border: 1px solid {BORDER_COLOR};"
            f" border-radius: 8px; }} QLabel {{ border: none; }}")
        t_layout = QVBoxLayout(tester)
        t_layout.setContentsMargins(12, 10, 12, 10)
        t_layout.setSpacing(6)
        t_head = QHBoxLayout()
        t_head.addWidget(_label("Regex tester"))
        t_head.addStretch()
        self.test_result = QLabel("Type a sample below to test the regex")
        self.test_result.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        t_head.addWidget(self.test_result)
        t_layout.addLayout(t_head)
        self.sample_edit = QLineEdit()
        self.sample_edit.setPlaceholderText("Paste a sample string here...")
        t_layout.addWidget(self.sample_edit)
        root.addWidget(tester)

        self.error_lbl = QLabel("")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.setStyleSheet(f"color: {COLOR_RED}; font-size: 12px;")
        self.error_lbl.hide()
        root.addWidget(self.error_lbl)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.save_btn = QPushButton("Save Changes" if self._editing else "Add Rule")
        self.save_btn.setStyleSheet(_PRIMARY_BTN)
        self.save_btn.setDefault(True)
        self.save_btn.clicked.connect(self._on_save)
        buttons.addWidget(cancel)
        buttons.addWidget(self.save_btn)
        root.addLayout(buttons)

        self.regex_edit.textChanged.connect(self._run_test)
        self.sample_edit.textChanged.connect(self._run_test)

        if rule:
            self._load(rule)

    # ------------------------------------------------------------------ #
    def _load(self, rule: dict) -> None:
        self.id_edit.setText(rule["pattern_id"])
        self.id_edit.setReadOnly(True)  # the ID is the rule's identity
        self.id_edit.setToolTip("The ID of an existing rule cannot be changed.")
        self.name_edit.setText(rule["name"])
        self.category_combo.setCurrentText(rule["category"])
        self.severity_combo.setCurrentText(rule["severity"])
        self.provider_edit.setText(rule.get("provider", ""))
        self.confidence_spin.setValue(float(rule["base_confidence"]))
        self.regex_edit.setText(rule["regex"])
        self.desc_edit.setPlainText(rule.get("description", ""))
        self.enabled_chk.setChecked(bool(rule.get("enabled", True)))
        self.entropy_chk.setChecked(bool(rule.get("entropy_required", False)))
        self.context_chk.setChecked(bool(rule.get("context_required", False)))

    def _run_test(self) -> None:
        pattern, sample = self.regex_edit.text().strip(), self.sample_edit.text()
        if not pattern or not sample:
            self._set_test("Type a sample below to test the regex", TEXT_MUTED)
            return
        try:
            match = re.compile(pattern, re.IGNORECASE).search(sample)
        except re.error as exc:
            self._set_test(f"⚠ Invalid regex: {exc}", COLOR_YELLOW)
            return
        if match:
            self._set_test(f"✔ Match: '{match.group(0)}'", COLOR_GREEN)
        else:
            self._set_test("✘ No match", COLOR_RED)

    def _set_test(self, text: str, color: str) -> None:
        self.test_result.setText(text)
        self.test_result.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 600;")

    def _on_save(self) -> None:
        raw = {
            "pattern_id": self.id_edit.text(),
            "name": self.name_edit.text(),
            "category": self.category_combo.currentText(),
            "severity": self.severity_combo.currentText(),
            "provider": self.provider_edit.text(),
            "base_confidence": self.confidence_spin.value(),
            "regex": self.regex_edit.text(),
            "description": self.desc_edit.toPlainText(),
            "enabled": self.enabled_chk.isChecked(),
            "entropy_required": self.entropy_chk.isChecked(),
            "context_required": self.context_chk.isChecked(),
        }
        try:
            self._result = RuleStore.clean_rule(raw)
        except RuleConfigurationError as exc:
            self.error_lbl.setText(f"⚠ {exc}")
            self.error_lbl.show()
            return
        self.accept()

    def rule(self) -> Optional[dict]:
        """The validated rule after the dialog was accepted."""
        return self._result


class ValueDialog(QDialog):
    """Small popup asking for one text value (add or edit a file-rule entry)."""

    def __init__(
        self,
        parent=None,
        *,
        title: str,
        label: str,
        hint: str = "",
        placeholder: str = "",
        value: str = "",
        validator: Optional[Callable[[str], Optional[str]]] = None,
    ):
        super().__init__(parent)
        self._validator = validator
        self.setModal(True)
        self.setMinimumWidth(420)
        self.setStyleSheet(_DIALOG_STYLE)
        self.setWindowTitle(title)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(10)

        head = QLabel(title)
        head.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 16px; font-weight: 700;")
        root.addWidget(head)
        if hint:
            root.addWidget(_label(hint, muted=True))

        root.addWidget(_label(label))
        self.edit = QLineEdit(value)
        self.edit.setPlaceholderText(placeholder)
        self.edit.returnPressed.connect(self._on_ok)
        root.addWidget(self.edit)

        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(f"color: {COLOR_RED}; font-size: 12px;")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.hide()
        root.addWidget(self.error_lbl)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("Save")
        ok.setStyleSheet(_PRIMARY_BTN)
        ok.clicked.connect(self._on_ok)
        buttons.addWidget(cancel)
        buttons.addWidget(ok)
        root.addLayout(buttons)

        self.edit.setFocus()
        self.edit.selectAll()

    def _on_ok(self) -> None:
        text = self.edit.text().strip()
        error = "A value is required." if not text else (
            self._validator(text) if self._validator else None)
        if error:
            self.error_lbl.setText(f"⚠ {error}")
            self.error_lbl.show()
            return
        self.accept()

    def value(self) -> str:
        return self.edit.text().strip()
