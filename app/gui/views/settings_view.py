"""
Settings View
Form-based editor for the detection rules (config/pattern_rules.yaml) and the
file eligibility rules (config/file_rules.yaml).

* Detection rules are shown in a table of the rules currently in effect
  (built-in + overrides + custom). Rules are enabled/disabled with a checkbox,
  edited through a popup form (double-click a row or press Edit) and new rules
  are added through the same popup.
* File rules are shown as four lists with Add / Edit / Remove buttons.

No raw YAML editing is required; every change is validated before it is saved
and the live detection engine is reloaded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from app.gui.theme import (
    ACCENT_BLUE, BG_CARD, BG_INPUT, BORDER_COLOR, COLOR_GREEN, COLOR_RED,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, get_severity_colors,
)
from app.gui.views.rule_dialogs import PatternRuleDialog, ValueDialog
from config.rule_loader import RuleConfigurationError

if TYPE_CHECKING:
    from app.gui.backend_bridge import BackendBridge

_SECONDARY_BTN = f"""
QPushButton {{
    background-color: #1E2E4A; color: #FFFFFF; border: 1px solid #3B527E;
    border-radius: 8px; padding: 8px 16px; font-weight: 700;
}}
QPushButton:hover {{ background-color: #2A3F66; border-color: {ACCENT_BLUE}; }}
QPushButton:disabled {{ color: #64748B; background-color: #131B2E; border-color: #1E2B45; }}
"""

_PRIMARY_BTN = f"""
QPushButton {{
    background-color: {ACCENT_BLUE}; color: #FFFFFF; border: 1px solid #38BDF8;
    border-radius: 8px; padding: 8px 16px; font-weight: 700;
}}
QPushButton:hover {{ background-color: #006ED3; border-color: #60A5FA; }}
"""

_ROW_BTN = f"""
QPushButton {{
    background-color: #1E2E4A; color: #FFFFFF; border: 1px solid #3B527E;
    border-radius: 6px; padding: 3px 10px; font-size: 12px; font-weight: 600;
}}
QPushButton:hover {{ background-color: #2A3F66; border-color: {ACCENT_BLUE}; }}
QPushButton:disabled {{ color: #475569; background-color: #101726; border-color: #1E2B45; }}
"""

_TABLE_STYLE = f"""
QTableWidget::indicator {{
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid #3B527E; background-color: {BG_INPUT};
}}
QTableWidget::indicator:checked {{ background-color: {ACCENT_BLUE}; border-color: {ACCENT_BLUE}; }}
"""

_LIST_STYLE = f"""
QListWidget {{
    background-color: {BG_INPUT}; border: 1px solid {BORDER_COLOR};
    border-radius: 8px; padding: 4px; outline: none;
}}
QListWidget::item {{ padding: 6px 8px; border-radius: 4px; }}
QListWidget::item:selected {{ background-color: rgba(0, 132, 255, 0.25); color: #FFFFFF; }}
QListWidget::item:hover {{ background-color: rgba(0, 132, 255, 0.12); }}
"""

_CARD_STYLE = f"""
QFrame#ruleCard {{
    background-color: {BG_CARD}; border: 1px solid {BORDER_COLOR}; border-radius: 10px;
}}
QFrame#ruleCard QLabel {{ background: transparent; border: none; padding: 0px; }}
"""

_SOURCE_LABELS = {"built-in": "Built-in", "modified": "Built-in (modified)", "custom": "Custom"}

# Pattern table columns
COL_ENABLED, COL_NAME, COL_ID, COL_CATEGORY, COL_PROVIDER, COL_SEVERITY, COL_CONF, COL_SOURCE, COL_ACTIONS = range(9)


class SettingsView(QWidget):
    """Rule configuration screen (form based)."""

    def __init__(self, bridge: "BackendBridge", parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self._rules: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(16)

        # Header
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("⚙️ Security Agent Configuration")
        title.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        sub = QLabel("Manage the detection rules and file scanning filters used by the scanner.")
        sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()

        self.reload_btn = QPushButton("🔄 Reload Rules")
        self.reload_btn.setStyleSheet(_SECONDARY_BTN)
        self.reload_btn.clicked.connect(self.reload_all_rules)
        top_bar.addWidget(self.reload_btn)
        layout.addLayout(top_bar)

        self.tabs = QTabWidget()
        self.tab_patterns = self.create_pattern_rules_tab()
        self.tabs.addTab(self.tab_patterns, "🔍 Detection Rules")
        self.tab_files = self.create_file_rules_tab()  # returns a scroll area
        self.tabs.addTab(self.tab_files, "📁 File Eligibility Rules")
        layout.addWidget(self.tabs, stretch=1)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        layout.addWidget(self.status_lbl)

        self.refresh_pattern_table()
        self.refresh_file_lists()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _status(self, text: str, ok: bool = True) -> None:
        color = COLOR_GREEN if ok else COLOR_RED
        self.status_lbl.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 600;")
        self.status_lbl.setText(text)

    def _error(self, title: str, exc: Exception) -> None:
        self._status(f"⚠ {title}", ok=False)
        QMessageBox.critical(self, title, str(exc))

    # ------------------------------------------------------------------ #
    # TAB 1: Detection rules
    # ------------------------------------------------------------------ #

    def create_pattern_rules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        toolbar = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔎 Search rules by name, ID, category or provider...")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_edit, stretch=1)

        self.count_lbl = QLabel("")
        self.count_lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px;")
        toolbar.addWidget(self.count_lbl)

        add_btn = QPushButton("➕ Add Rule")
        add_btn.setStyleSheet(_PRIMARY_BTN)
        add_btn.clicked.connect(self.add_pattern_rule)
        toolbar.addWidget(add_btn)
        layout.addLayout(toolbar)

        hint = QLabel(
            "Tick the box to enable or disable a rule. Double-click a row (or press Edit) to change it. "
            "Built-in rules cannot be deleted, only disabled or reset to their defaults."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(hint)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["On", "Name", "Pattern ID", "Category", "Provider", "Severity", "Confidence", "Source", ""]
        )
        self.table.setStyleSheet(_TABLE_STYLE)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(COL_ENABLED, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Stretch)
        for col in (COL_ID, COL_CATEGORY, COL_PROVIDER, COL_SEVERITY, COL_CONF, COL_SOURCE, COL_ACTIONS):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemChanged.connect(self._on_item_changed)
        self.table.cellDoubleClicked.connect(lambda row, _col: self._edit_row(row))
        layout.addWidget(self.table, stretch=1)

        return widget

    def _schedule_refresh(self) -> None:
        """Rebuild the table after the current signal handler returns (it may be called
        from a widget that the rebuild is about to destroy)."""
        QTimer.singleShot(0, self.refresh_pattern_table)

    def refresh_pattern_table(self) -> None:
        try:
            self._rules = self.bridge.list_pattern_rules()
        except Exception as exc:  # corrupt YAML etc.
            self._rules = []
            self._error("Could not load detection rules", exc)

        self.table.blockSignals(True)
        self.table.setRowCount(len(self._rules))
        for row, rule in enumerate(self._rules):
            self._fill_row(row, rule)
        self.table.blockSignals(False)
        self._apply_filter()

    def _fill_row(self, row: int, rule: dict) -> None:
        enabled = rule["enabled"]
        text_color = QColor(TEXT_PRIMARY if enabled else TEXT_MUTED)

        def make(text: str, align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft) -> QTableWidgetItem:
            item = QTableWidgetItem(text)
            item.setForeground(QBrush(text_color))
            item.setTextAlignment(align)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            return item

        check = QTableWidgetItem()
        check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsUserCheckable)
        check.setCheckState(Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked)
        check.setData(Qt.ItemDataRole.UserRole, rule["pattern_id"])
        check.setToolTip("Enable / disable this rule")
        self.table.setItem(row, COL_ENABLED, check)

        self.table.setItem(row, COL_NAME, make(rule["name"]))
        self.table.setItem(row, COL_ID, make(rule["pattern_id"]))
        self.table.setItem(row, COL_CATEGORY, make(rule["category"]))
        self.table.setItem(row, COL_PROVIDER, make(rule["provider"] or "—"))

        sev = make(rule["severity"].upper())
        sev.setForeground(QBrush(QColor(get_severity_colors(rule["severity"])[0] if enabled else TEXT_MUTED)))
        self.table.setItem(row, COL_SEVERITY, sev)
        self.table.setItem(row, COL_CONF, make(f"{rule['base_confidence']:.2f}"))
        self.table.setItem(row, COL_SOURCE, make(_SOURCE_LABELS.get(rule["source"], rule["source"])))

        for col in (COL_NAME, COL_ID):
            self.table.item(row, col).setToolTip(rule.get("description") or rule["regex"])

        # Row action buttons
        actions = QWidget()
        a_layout = QHBoxLayout(actions)
        a_layout.setContentsMargins(4, 0, 4, 0)
        a_layout.setSpacing(6)

        edit_btn = QPushButton("✏ Edit")
        edit_btn.setStyleSheet(_ROW_BTN)
        edit_btn.clicked.connect(lambda _=False, pid=rule["pattern_id"]: self._edit_by_id(pid))
        a_layout.addWidget(edit_btn)

        if rule["source"] == "custom":
            del_btn = QPushButton("🗑 Delete")
            del_btn.setStyleSheet(_ROW_BTN)
        else:
            del_btn = QPushButton("↺ Reset")
            del_btn.setStyleSheet(_ROW_BTN)
            del_btn.setEnabled(rule["source"] == "modified")
            del_btn.setToolTip("Restore this built-in rule to its default settings")
        del_btn.clicked.connect(lambda _=False, pid=rule["pattern_id"]: self.delete_pattern_rule(pid))
        a_layout.addWidget(del_btn)
        self.table.setCellWidget(row, COL_ACTIONS, actions)

    def _apply_filter(self) -> None:
        needle = self.search_edit.text().strip().casefold()
        visible = 0
        for row, rule in enumerate(self._rules):
            haystack = " ".join(
                str(rule.get(k, "")) for k in ("name", "pattern_id", "category", "provider", "severity", "source")
            ).casefold()
            hide = bool(needle) and needle not in haystack
            self.table.setRowHidden(row, hide)
            visible += 0 if hide else 1
        enabled = sum(1 for r in self._rules if r["enabled"])
        self.count_lbl.setText(f"{visible} shown · {enabled}/{len(self._rules)} enabled")

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != COL_ENABLED:
            return
        pattern_id = item.data(Qt.ItemDataRole.UserRole)
        enabled = item.checkState() == Qt.CheckState.Checked
        try:
            self.bridge.set_pattern_enabled(pattern_id, enabled)
            self._status(f"{'Enabled' if enabled else 'Disabled'} rule '{pattern_id}'. Detection engine reloaded.")
        except Exception as exc:
            self._error("Could not update rule", exc)
        self._schedule_refresh()

    def _edit_row(self, row: int) -> None:
        if 0 <= row < len(self._rules):
            self._edit_by_id(self._rules[row]["pattern_id"])

    def _edit_by_id(self, pattern_id: str) -> None:
        rule = next((r for r in self._rules if r["pattern_id"] == pattern_id), None)
        if rule is None:
            return
        dialog = PatternRuleDialog(self, rule)
        if dialog.exec() != PatternRuleDialog.DialogCode.Accepted:
            return
        try:
            self.bridge.save_pattern_rule(dialog.rule(), original_id=pattern_id)
            self._status(f"Saved changes to '{pattern_id}'. Detection engine reloaded.")
        except Exception as exc:
            self._error("Could not save rule", exc)
        self._schedule_refresh()

    def add_pattern_rule(self) -> None:
        dialog = PatternRuleDialog(self)
        while dialog.exec() == PatternRuleDialog.DialogCode.Accepted:
            rule = dialog.rule()
            try:
                self.bridge.save_pattern_rule(rule)
            except RuleConfigurationError as exc:
                # e.g. duplicate ID: keep the popup (and the user's input) open
                dialog.error_lbl.setText(f"⚠ {exc}")
                dialog.error_lbl.show()
                continue
            except Exception as exc:
                self._error("Could not add rule", exc)
                break
            self._status(f"Added rule '{rule['pattern_id']}'. Detection engine reloaded.")
            break
        self._schedule_refresh()

    def delete_pattern_rule(self, pattern_id: str) -> None:
        rule = next((r for r in self._rules if r["pattern_id"] == pattern_id), None)
        if rule is None:
            return
        is_custom = rule["source"] == "custom"
        verb = "Delete" if is_custom else "Reset"
        message = (
            f"Delete the custom rule '{rule['name']}'? This cannot be undone."
            if is_custom else
            f"Reset the built-in rule '{rule['name']}' to its default settings?"
        )
        answer = QMessageBox.question(
            self, f"{verb} Rule", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.bridge.delete_pattern_rule(pattern_id)
            done = "Deleted" if is_custom else "Reset"
            self._status(f"{done} rule '{pattern_id}'. Detection engine reloaded.")
        except Exception as exc:
            self._error(f"Could not {verb.lower()} rule", exc)
        self._schedule_refresh()

    # ------------------------------------------------------------------ #
    # TAB 2: File eligibility rules
    # ------------------------------------------------------------------ #

    def create_file_rules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        intro = QLabel(
            "Choose which files the scanner looks at. A file is scanned if it matches an included "
            "filename, extension or name pattern, and is not inside an excluded directory."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(intro)

        grid = QGridLayout()
        grid.setSpacing(14)
        self._file_lists: dict[str, QListWidget] = {}

        sections = [
            ("included_filenames", "Included filenames",
             "Exact file names that are always scanned.", "e.g. .env, dockerfile",
             self._validate_filename),
            ("included_extensions", "Included extensions",
             "File extensions that are scanned (start with a dot).", "e.g. .json",
             self._validate_extension),
            ("included_name_patterns", "Included name patterns",
             "Files named <pattern>.*, <pattern>-* or <pattern>_* are scanned.", "e.g. settings, config",
             self._validate_filename),
            ("excluded_directories", "Excluded directories",
             "Anything inside a directory with one of these names is skipped.", "e.g. node_modules, .git",
             self._validate_directory),
        ]
        for index, (key, title, desc, placeholder, validator) in enumerate(sections):
            grid.addWidget(self._build_file_card(key, title, desc, placeholder, validator), index // 2, index % 2)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid, stretch=1)

        # Scroll when the window is too small to show all four lists comfortably.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        scroll.viewport().setStyleSheet("background: transparent;")
        scroll.setWidget(widget)
        return scroll

    def _build_file_card(self, key: str, title: str, desc: str, placeholder: str,
                         validator: Callable[[str], Optional[str]]) -> QFrame:
        card = QFrame()
        card.setObjectName("ruleCard")
        card.setStyleSheet(_CARD_STYLE)
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        head = QLabel(title)
        head.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
        c_layout.addWidget(head)
        sub = QLabel(desc)
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
        c_layout.addWidget(sub)

        lst = QListWidget()
        lst.setStyleSheet(_LIST_STYLE)
        lst.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        lst.setMinimumHeight(140)
        self._file_lists[key] = lst
        c_layout.addWidget(lst, stretch=1)

        buttons = QHBoxLayout()
        add_btn = QPushButton("➕ Add")
        add_btn.setStyleSheet(_PRIMARY_BTN)
        edit_btn = QPushButton("✏ Edit")
        edit_btn.setStyleSheet(_SECONDARY_BTN)
        remove_btn = QPushButton("🗑 Remove")
        remove_btn.setStyleSheet(_SECONDARY_BTN)
        edit_btn.setEnabled(False)
        remove_btn.setEnabled(False)
        for btn in (add_btn, edit_btn, remove_btn):
            buttons.addWidget(btn)
        buttons.addStretch()
        c_layout.addLayout(buttons)

        def on_selection() -> None:
            has = lst.currentItem() is not None
            edit_btn.setEnabled(has)
            remove_btn.setEnabled(has)

        lst.itemSelectionChanged.connect(on_selection)
        lst.itemDoubleClicked.connect(lambda _i: self._edit_file_value(key, title, placeholder, validator))
        add_btn.clicked.connect(lambda: self._add_file_value(key, title, desc, placeholder, validator))
        edit_btn.clicked.connect(lambda: self._edit_file_value(key, title, placeholder, validator))
        remove_btn.clicked.connect(lambda: self._remove_file_value(key))
        return card

    # -- validators (return an error message or None)
    @staticmethod
    def _validate_filename(value: str) -> Optional[str]:
        if "/" in value or "\\" in value:
            return "Enter a file name only, without a path."
        return None

    @staticmethod
    def _validate_extension(value: str) -> Optional[str]:
        if not value.startswith(".") or len(value) < 2 or "/" in value or "\\" in value or " " in value:
            return "An extension must start with a dot, e.g. .json"
        return None

    @staticmethod
    def _validate_directory(value: str) -> Optional[str]:
        if "/" in value or "\\" in value:
            return "Enter a directory name only (e.g. node_modules), not a path."
        return None

    # -- list handling
    def refresh_file_lists(self) -> None:
        try:
            rules = self.bridge.get_file_rules()
        except Exception as exc:
            rules = {key: [] for key in self._file_lists}
            self._error("Could not load file rules", exc)
        for key, lst in self._file_lists.items():
            lst.clear()
            for value in rules.get(key, []):
                lst.addItem(QListWidgetItem(value))

    def _current_values(self) -> dict[str, list[str]]:
        return {
            key: [lst.item(i).text() for i in range(lst.count())]
            for key, lst in self._file_lists.items()
        }

    def _persist_file_rules(self, rules: dict[str, list[str]], message: str) -> None:
        try:
            self.bridge.save_file_rules(rules)
            self._status(f"{message} File filter reloaded.")
        except Exception as exc:
            self._error("Could not save file rules", exc)
        QTimer.singleShot(0, self.refresh_file_lists)

    def _add_file_value(self, key: str, title: str, desc: str, placeholder: str, validator) -> None:
        existing = {v.casefold() for v in self._current_values()[key]}

        def check(value: str) -> Optional[str]:
            if value.casefold() in existing:
                return f"'{value}' is already in the list."
            return validator(value)

        dialog = ValueDialog(self, title=f"Add to {title}", label="Value", hint=desc,
                             placeholder=placeholder, validator=check)
        if dialog.exec() != ValueDialog.DialogCode.Accepted:
            return
        rules = self._current_values()
        rules[key].append(dialog.value())
        self._persist_file_rules(rules, f"Added '{dialog.value()}'.")

    def _edit_file_value(self, key: str, title: str, placeholder: str, validator) -> None:
        lst = self._file_lists[key]
        row = lst.currentRow()
        if row < 0:
            return
        old = lst.item(row).text()
        others = {v.casefold() for i, v in enumerate(self._current_values()[key]) if i != row}

        def check(value: str) -> Optional[str]:
            if value.casefold() in others:
                return f"'{value}' is already in the list."
            return validator(value)

        dialog = ValueDialog(self, title=f"Edit {title}", label="Value", placeholder=placeholder,
                             value=old, validator=check)
        if dialog.exec() != ValueDialog.DialogCode.Accepted:
            return
        rules = self._current_values()
        rules[key][row] = dialog.value()
        self._persist_file_rules(rules, f"Updated '{old}'.")

    def _remove_file_value(self, key: str) -> None:
        lst = self._file_lists[key]
        row = lst.currentRow()
        if row < 0:
            return
        value = lst.item(row).text()
        answer = QMessageBox.question(
            self, "Remove Entry", f"Remove '{value}' from this list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        rules = self._current_values()
        del rules[key][row]
        self._persist_file_rules(rules, f"Removed '{value}'.")

    # ------------------------------------------------------------------ #

    def reload_all_rules(self) -> None:
        try:
            self.bridge.reload_rules()
        except Exception as exc:
            self._error("Reload Error", exc)
            return
        self.refresh_pattern_table()
        self.refresh_file_lists()
        self._status("All detection and file filtering rules reloaded from disk.")
