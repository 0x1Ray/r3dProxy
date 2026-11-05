"""Proxy tab: live intercept queue (edit/forward/drop) + full HTTP history."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QAction
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QTableWidget, QTableWidgetItem,
                               QHeaderView, QLineEdit, QGroupBox, QMenu, QAbstractItemView,
                               QTabWidget, QCheckBox)

from . import theme
from .editor import HttpEditor

COLS = ["#", "Time", "Method", "Host", "Path", "Status", "Len", "Type"]


class ProxyTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.row_by_fid = {}
        self._current_intercept_fid = None

        root = QVBoxLayout(self)
        splitter = QSplitter(Qt.Vertical)
        root.addWidget(splitter)

        splitter.addWidget(self._build_intercept_panel())
        splitter.addWidget(self._build_history_panel())
        splitter.setSizes([260, 560])

    # ---------------- intercept panel ----------------
    def _build_intercept_panel(self):
        box = QGroupBox("Intercept")
        v = QVBoxLayout(box)

        bar = QHBoxLayout()
        self.queue_label = QLabel("queue: 0 waiting")
        self.fwd_btn = QPushButton("Forward")
        self.fwd_btn.setObjectName("accent")
        self.drop_btn = QPushButton("Drop")
        self.fwd_all_btn = QPushButton("Forward all")
        self.to_rep_btn = QPushButton("→ Repeater")
        self.fwd_btn.clicked.connect(self.forward_current)
        self.drop_btn.clicked.connect(self.drop_current)
        self.fwd_all_btn.clicked.connect(self.forward_all)
        self.to_rep_btn.clicked.connect(self.intercept_to_repeater)
        bar.addWidget(self.queue_label)
        bar.addStretch(1)
        for b in (self.to_rep_btn, self.drop_btn, self.fwd_all_btn, self.fwd_btn):
            bar.addWidget(b)
        v.addLayout(bar)

        self.intercept_editor = HttpEditor(read_only=False)
        self.intercept_editor.setPlaceholderText(
            "Intercepted requests appear here. Turn on 'Intercept' in the toolbar. "
            "Edit freely, then Forward.")
        v.addWidget(self.intercept_editor)
        self._set_intercept_enabled(False)
        return box

    def _set_intercept_enabled(self, on):
        for b in (self.fwd_btn, self.drop_btn, self.to_rep_btn):
            b.setEnabled(on)
        self.intercept_editor.setReadOnly(not on)

    def refresh_intercept_queue(self):
        pending = self.ctx.engine.pending()
        self.queue_label.setText(f"queue: {len(pending)} waiting")
        self.fwd_all_btn.setEnabled(bool(pending))
        if not pending:
            self._current_intercept_fid = None
            self.intercept_editor.set_text("")
            self._set_intercept_enabled(False)
            return
        fid = pending[0]
        if fid != self._current_intercept_fid:
            self._current_intercept_fid = fid
            rec = self.ctx.store.get(fid)
            self.intercept_editor.set_text(rec.request_text if rec else "")
        self._set_intercept_enabled(True)

    def forward_current(self):
        fid = self._current_intercept_fid
        if not fid:
            return
        self.ctx.engine.forward(fid, edited_text=self.intercept_editor.text())
        self._current_intercept_fid = None
        self.refresh_intercept_queue()

    def drop_current(self):
        fid = self._current_intercept_fid
        if not fid:
            return
        self.ctx.engine.drop(fid)
        self._current_intercept_fid = None
        self.refresh_intercept_queue()

    def forward_all(self):
        # Forward current with edits first, then the rest untouched.
        if self._current_intercept_fid:
            self.forward_current()
        for fid in self.ctx.engine.pending():
            self.ctx.engine.forward(fid)
        self.refresh_intercept_queue()

    def intercept_to_repeater(self):
        fid = self._current_intercept_fid
        rec = self.ctx.store.get(fid) if fid else None
        if rec:
            # Use whatever is currently in the editor.
            rec.request_text = self.intercept_editor.text()
            self.main.send_to_repeater(rec)

    # ---------------- history panel ----------------
    def _build_history_panel(self):
        box = QGroupBox("HTTP history")
        v = QVBoxLayout(box)

        bar = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("search (host/path/method — or regex over req+resp with 'deep')…")
        self.filter_edit.textChanged.connect(lambda: self.apply_filter())
        self.deep_search = QCheckBox("deep")
        self.deep_search.setToolTip("Regex search across full request + response bodies")
        self.deep_search.toggled.connect(lambda: self.apply_filter())
        clear_btn = QPushButton("Clear history")
        clear_btn.clicked.connect(self.clear_history)
        bar.addWidget(self.filter_edit)
        bar.addWidget(self.deep_search)
        bar.addWidget(clear_btn)
        v.addLayout(bar)

        inner = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        for c in (0, 1, 2, 5, 6):
            hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        inner.addWidget(self.table)

        viewers = QTabWidget()
        self.req_view = HttpEditor(read_only=True)
        self.resp_view = HttpEditor(read_only=True)
        viewers.addTab(self.req_view, "Request")
        viewers.addTab(self.resp_view, "Response")
        inner.addWidget(viewers)
        inner.setSizes([300, 260])

        v.addWidget(inner)
        return box

    def _row_values(self, rec):
        return [
            str(self.row_by_fid.get(rec.fid, "") + 1) if rec.fid in self.row_by_fid else "",
            rec.time_str, rec.method, rec.host, _path_of(rec.url),
            "" if rec.status is None else str(rec.status),
            "" if rec.length is None else str(rec.length),
            (rec.mime.split(";")[0] if rec.mime else ""),
        ]

    def _ensure_row(self, rec):
        if rec.fid in self.row_by_fid:
            return self.row_by_fid[rec.fid]
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.row_by_fid[rec.fid] = row
        for c in range(len(COLS)):
            self.table.setItem(row, c, QTableWidgetItem(""))
        self.table.item(row, 0).setData(Qt.UserRole, rec.fid)
        return row

    def _paint_row(self, rec):
        row = self._ensure_row(rec)
        vals = self._row_values(rec)
        vals[0] = str(row + 1)
        for c, val in enumerate(vals):
            item = self.table.item(row, c)
            item.setText(val)
        # Colour status codes.
        st = rec.status
        color = None
        if st is not None:
            if 200 <= st < 300:
                color = QColor(theme.OK)
            elif 300 <= st < 400:
                color = QColor(theme.WARN)
            elif st >= 400:
                color = QColor(theme.ACCENT)
        if color:
            self.table.item(row, 5).setForeground(color)
        if rec.intercepted:
            self.table.item(row, 2).setForeground(QColor(theme.WARN))

    # ---------------- engine signal slots ----------------
    def on_request_captured(self, fid):
        rec = self.ctx.store.get(fid)
        if rec:
            self._paint_row(rec)
            self.apply_filter(self.filter_edit.text())

    def on_response_captured(self, fid):
        rec = self.ctx.store.get(fid)
        if rec:
            self._paint_row(rec)
            if self._selected_fid() == fid:
                self.resp_view.set_text(rec.response_text)

    def on_request_intercepted(self, fid):
        rec = self.ctx.store.get(fid)
        if rec:
            self._paint_row(rec)
        self.refresh_intercept_queue()

    def on_flow_error(self, fid, msg):
        rec = self.ctx.store.get(fid)
        if rec and fid in self.row_by_fid:
            row = self.row_by_fid[fid]
            self.table.item(row, 5).setText("ERR")
            self.table.item(row, 5).setForeground(QColor(theme.ACCENT))
            self.table.item(row, 7).setText(msg[:40])

    # ---------------- interaction ----------------
    def _selected_fid(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        item = self.table.item(row, 0)
        return item.data(Qt.UserRole) if item else None

    def on_row_selected(self):
        fid = self._selected_fid()
        rec = self.ctx.store.get(fid) if fid else None
        if rec:
            self.req_view.set_text(rec.request_text)
            self.resp_view.set_text(rec.response_text)

    def apply_filter(self, _=None):
        import re
        q = self.filter_edit.text().strip()
        deep = self.deep_search.isChecked()
        rx = None
        if deep and q:
            try:
                rx = re.compile(q, re.I)
            except re.error:
                rx = None
        for fid, row in self.row_by_fid.items():
            rec = self.ctx.store.get(fid)
            if not rec:
                continue
            if not q:
                hide = False
            elif deep:
                hay = f"{rec.method} {rec.url}\n{rec.request_text}\n{rec.response_text}"
                hide = (rx.search(hay) is None) if rx else (q.lower() not in hay.lower())
            else:
                hay = f"{rec.method} {rec.host} {rec.url}".lower()
                hide = q.lower() not in hay
            self.table.setRowHidden(row, hide)

    def clear_history(self):
        self.table.setRowCount(0)
        self.row_by_fid.clear()
        self.ctx.store.clear()
        self.req_view.set_text("")
        self.resp_view.set_text("")

    def rebuild_from_store(self):
        """Repaint the history table from the current store (e.g. after load)."""
        self.table.setRowCount(0)
        self.row_by_fid.clear()
        for rec in self.ctx.store.all():
            self._paint_row(rec)
        self.apply_filter(self.filter_edit.text())

    def show_context_menu(self, pos):
        fid = self._selected_fid()
        if not fid:
            idx = self.table.indexAt(pos)
            if idx.isValid():
                self.table.selectRow(idx.row())
                fid = self._selected_fid()
        if not fid:
            return
        rec = self.ctx.store.get(fid)
        if not rec:
            return
        menu = QMenu(self)
        a_rep = menu.addAction("Send to Repeater")
        a_intr = menu.addAction("Send to Intruder")
        a_scan = menu.addAction("Send to Scanner")
        a_seq = menu.addAction("Send to Sequencer")
        a_ai = menu.addAction("Send to AI Assistant")
        a_csrf = menu.addAction("Generate CSRF PoC")
        menu.addSeparator()
        a_copyurl = menu.addAction("Copy URL")
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if act == a_rep:
            self.main.send_to_repeater(rec)
        elif act == a_intr:
            self.main.send_to_intruder(rec)
        elif act == a_scan:
            self.main.send_to_scanner(rec)
        elif act == a_seq:
            self.main.send_to_sequencer(rec)
        elif act == a_csrf:
            self.main.send_to_csrf(rec)
        elif act == a_ai:
            self.main.send_to_ai(rec.request_text, rec.response_text)
        elif act == a_copyurl:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(rec.url)


def _path_of(url):
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.path or "/") + (("?" + p.query) if p.query else "")
    except Exception:
        return url
