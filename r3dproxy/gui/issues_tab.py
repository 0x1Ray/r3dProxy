"""Issues tab: passive findings discovered while browsing through the proxy."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QCheckBox, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QPlainTextEdit, QMenu)

from . import theme
from ..core import passive
from ..core.passive import SEV_ORDER

SEV_COLOR = {"High": theme.ACCENT, "Medium": "#ff7043", "Low": theme.WARN, "Info": theme.FG_DIM}


class _SevItem(QTableWidgetItem):
    def __init__(self, sev):
        super().__init__(sev)
        self._o = SEV_ORDER.get(sev, 9)
        self.setForeground(QColor(SEV_COLOR.get(sev, theme.FG)))
    def __lt__(self, other):
        return self._o < getattr(other, "_o", 9)


class IssuesTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self._issues = []
        self._seen = set()

        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.enabled = QCheckBox("Passive scanning")
        self.enabled.setChecked(bool(self.ctx.config.get("passive_enabled", True)))
        self.enabled.toggled.connect(self._toggle)
        self.count_lbl = QLabel("0 issues")
        clear = QPushButton("Clear"); clear.clicked.connect(self.clear)
        bar.addWidget(self.enabled); bar.addStretch(1); bar.addWidget(self.count_lbl); bar.addWidget(clear)
        v.addLayout(bar)

        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Issue", "Confidence", "URL"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        split.addWidget(self.table)
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True)
        self.detail.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        split.addWidget(self.detail)
        split.setSizes([400, 220])
        v.addWidget(split)

    def _toggle(self, on):
        self.ctx.config["passive_enabled"] = bool(on)
        self.ctx.config.save()

    # called from main window on each captured response
    def audit_record(self, rec):
        if not self.enabled.isChecked() or not rec or not rec.response_text:
            return
        # scope: if a scope is set, only audit in-scope hosts
        scope = self.ctx.config.get("scope") or []
        if scope and not any(s.lower() in (rec.host or "").lower() for s in scope if s.strip()):
            return
        try:
            found = passive.audit(rec.request_text, rec.response_text, rec.url)
        except Exception:
            return
        for iss in found:
            if iss.key() in self._seen:
                continue
            self._seen.add(iss.key())
            self._add(iss, rec)

    def _add(self, iss, rec):
        self._issues.append((iss, rec))
        self.table.setSortingEnabled(False)
        row = self.table.rowCount()
        self.table.insertRow(row)
        sev = _SevItem(iss.severity)
        sev.setData(Qt.UserRole, len(self._issues) - 1)
        self.table.setItem(row, 0, sev)
        self.table.setItem(row, 1, QTableWidgetItem(iss.name))
        self.table.setItem(row, 2, QTableWidgetItem(iss.confidence))
        self.table.setItem(row, 3, QTableWidgetItem(iss.url))
        self.table.setSortingEnabled(True)
        self.count_lbl.setText(f"{self.table.rowCount()} issues")

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        li = item.data(Qt.UserRole) if item else None
        if li is None or li >= len(self._issues):
            return None
        return self._issues[li]

    def show_detail(self):
        sel = self._selected()
        if not sel:
            return
        iss, rec = sel
        lines = [f"{iss.severity} · {iss.confidence}", iss.name, "", iss.detail, "", f"URL: {iss.url}"]
        self.detail.setPlainText("\n".join(lines))

    def _menu(self, pos):
        sel = self._selected()
        if not sel:
            return
        iss, rec = sel
        menu = QMenu(self)
        a_rep = menu.addAction("Send request to Repeater")
        a_scan = menu.addAction("Send to Scanner")
        a_ai = menu.addAction("Send to AI Assistant")
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not rec:
            return
        if act == a_rep:
            self.main.send_to_repeater(rec)
        elif act == a_scan:
            self.main.send_to_scanner(rec)
        elif act == a_ai:
            self.main.send_to_ai(rec.request_text, rec.response_text)

    def clear(self):
        self.table.setRowCount(0)
        self._issues.clear()
        self._seen.clear()
        self.detail.clear()
        self.count_lbl.setText("0 issues")
