"""Scanner tab: run OWASP plugins against a single request at a §…§ point."""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QLineEdit, QComboBox, QSpinBox,
                               QListWidget, QListWidgetItem, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QGroupBox, QTabWidget, QCheckBox, QMenu)
from PySide6.QtGui import QColor

from . import theme
from .editor import HttpEditor
from ..core.sender import Target
from ..core.plugins import get_plugins
from ..core.plugins.base import ScanEngine, MARKER

CONF_COLOR = {"Firm": theme.ACCENT, "High": "#ff7043", "Tentative": theme.WARN, "Info": theme.FG_DIM}


class ScanWorker(QThread):
    finding = Signal(object)
    progress = Signal(str)
    done = Signal()

    def __init__(self, base_text, target, plugins, timeout, oast_base=None):
        super().__init__()
        self.base_text = base_text
        self.target = target
        self.plugins = plugins
        self.timeout = timeout
        self.oast_base = oast_base
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        for plugin in self.plugins:
            if self._stop:
                break
            self.progress.emit(f"▶ {plugin.name}")
            try:
                engine = ScanEngine(self.base_text, self.target, timeout=self.timeout,
                                    progress_cb=lambda label, resp: self.progress.emit(f"   {label} → {resp.status if resp.ok else resp.error}"),
                                    stop_flag=lambda: self._stop,
                                    oast_base=self.oast_base)
                engine.prepare()
                for f in plugin.run(engine):
                    self.finding.emit(f)
            except Exception as e:
                self.progress.emit(f"   ! {plugin.id} error: {e}")
        self.done.emit()


class ScannerTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None
        self._findings = []

        root = QVBoxLayout(self)
        info = QLabel("Mark the value to test with §…§, pick vulnerability plugins, and Scan. "
                      "Uses the raw-socket sender. Authorized testing only.")
        info.setWordWrap(True); info.setStyleSheet(f"color:{theme.FG_DIM};")
        root.addWidget(info)

        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        # left: request + target + plugins
        left = QWidget(); lv = QVBoxLayout(left)
        tbar = QHBoxLayout()
        tbar.addWidget(QLabel("Target:"))
        self.scheme = QComboBox(); self.scheme.addItems(["http", "https"])
        self.host = QLineEdit(); self.host.setPlaceholderText("host")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(80)
        tbar.addWidget(self.scheme); tbar.addWidget(self.host, 2)
        tbar.addWidget(QLabel(":")); tbar.addWidget(self.port)
        lv.addLayout(tbar)

        lv.addWidget(QLabel("Request — wrap the injection value in §…§:"))
        self.req_edit = HttpEditor(read_only=False)
        lv.addWidget(self.req_edit, 3)
        mbar = QHBoxLayout()
        mark_btn = QPushButton("Mark selection §§"); mark_btn.clicked.connect(self.mark_selection)
        mbar.addWidget(mark_btn); mbar.addStretch(1)
        lv.addLayout(mbar)

        pbox = QGroupBox("Plugins (OWASP)")
        pv = QVBoxLayout(pbox)
        selbar = QHBoxLayout()
        self.select_all = QCheckBox("select all"); self.select_all.setChecked(True)
        self.select_all.toggled.connect(self._toggle_all)
        self.use_oast = QCheckBox("use OAST")
        self.use_oast.setChecked(True)
        self.use_oast.setToolTip("Confirm blind SSRF/XXE/RCE via the OAST listener (start it in the OAST tab)")
        reload_btn = QPushButton("⟳ reload"); reload_btn.setMaximumWidth(80)
        reload_btn.clicked.connect(self.reload_plugins)
        selbar.addWidget(self.select_all); selbar.addWidget(self.use_oast)
        selbar.addStretch(1); selbar.addWidget(reload_btn)
        pv.addLayout(selbar)
        self.plugin_list = QListWidget()
        pv.addWidget(self.plugin_list)
        lv.addWidget(pbox, 2)

        rbar = QHBoxLayout()
        self.scan_btn = QPushButton("Scan"); self.scan_btn.setObjectName("accent")
        self.scan_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        self.export_btn = QPushButton("Export findings…")
        self.export_btn.clicked.connect(self.export_findings)
        rbar.addWidget(self.export_btn)
        rbar.addStretch(1); rbar.addWidget(self.stop_btn); rbar.addWidget(self.scan_btn)
        lv.addLayout(rbar)
        split.addWidget(left)

        # right: findings + log + viewer
        right = QWidget(); rv = QVBoxLayout(right)
        self.findings_tbl = QTableWidget(0, 5)
        self.findings_tbl.setHorizontalHeaderLabels(["Plugin", "OWASP", "Conf.", "Point", "Evidence"])
        self.findings_tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.findings_tbl.itemSelectionChanged.connect(self.show_finding)
        self.findings_tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_tbl.customContextMenuRequested.connect(self._ctx_menu)
        rv.addWidget(QLabel("Findings:"))
        rv.addWidget(self.findings_tbl, 2)

        viewers = QTabWidget()
        self.req_view = HttpEditor(read_only=True)
        self.resp_view = HttpEditor(read_only=True)
        from PySide6.QtWidgets import QPlainTextEdit
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        viewers.addTab(self.req_view, "Request")
        viewers.addTab(self.resp_view, "Response")
        viewers.addTab(self.log, "Log")
        rv.addWidget(viewers, 2)
        self.status = QLabel("idle"); self.status.setStyleSheet(f"color:{theme.FG_DIM};")
        rv.addWidget(self.status)
        split.addWidget(right)
        split.setSizes([560, 720])

        self.reload_plugins()

    # ---------- plugins ----------
    def reload_plugins(self):
        self.plugin_list.clear()
        for p in get_plugins():
            it = QListWidgetItem(f"{p.name}  —  {p.owasp}")
            it.setData(Qt.UserRole, p.id)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if self.select_all.isChecked() else Qt.Unchecked)
            it.setToolTip(p.description)
            self.plugin_list.addItem(it)

    def _toggle_all(self, on):
        for i in range(self.plugin_list.count()):
            self.plugin_list.item(i).setCheckState(Qt.Checked if on else Qt.Unchecked)

    def _selected_plugin_ids(self):
        ids = []
        for i in range(self.plugin_list.count()):
            it = self.plugin_list.item(i)
            if it.checkState() == Qt.Checked:
                ids.append(it.data(Qt.UserRole))
        return ids

    # ---------- load / mark ----------
    def load(self, request_text, target: Target):
        self.req_edit.set_text(request_text)
        self.scheme.setCurrentText(target.scheme)
        self.host.setText(target.host)
        self.port.setValue(target.port)

    def mark_selection(self):
        cur = self.req_edit.textCursor()
        if cur.selectedText():
            cur.insertText(f"{MARKER}{cur.selectedText()}{MARKER}")

    def current_target(self):
        return Target(self.host.text().strip(), self.port.value(),
                      self.scheme.currentText() == "https")

    # ---------- run ----------
    def start(self):
        tgt = self.current_target()
        if not tgt.host:
            self.status.setText("set a host"); return
        base = self.req_edit.text()
        ids = set(self._selected_plugin_ids())
        if not ids:
            self.status.setText("select at least one plugin"); return
        plugins = [p for p in get_plugins() if p.id in ids]
        marker_needed = any(p.uses_marker for p in plugins)
        if marker_needed and MARKER not in base:
            self.status.setText("add a §…§ injection marker (Mark selection)"); return

        self.findings_tbl.setRowCount(0)
        self._findings.clear()
        self.log.clear()
        self.req_view.set_text(""); self.resp_view.set_text("")
        self.scan_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        oast_base = self._resolve_oast_base() if self.use_oast.isChecked() else None
        self.status.setText("scanning…" + (f"  (OAST: {oast_base})" if oast_base else ""))
        self.worker = ScanWorker(base, tgt, plugins, self.ctx.config["sender_timeout"], oast_base)
        self.worker.finding.connect(self.on_finding)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def _resolve_oast_base(self):
        """Prefer a configured public base URL; else the running local listener."""
        base = (self.ctx.config.get("oast_base", "") or "").strip()
        if base:
            return base.rstrip("/")
        ot = getattr(self.main, "oast_tab", None)
        if ot and ot.listener.running:
            host = ot.host.text().strip() or "127.0.0.1"
            if host == "0.0.0.0":
                host = "127.0.0.1"
            return f"http://{host}:{ot.port.value()}"
        return None

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.status.setText("stopping…")

    def on_progress(self, line):
        self.log.appendPlainText(line)

    def on_finding(self, f):
        self._findings.append(f)
        row = self.findings_tbl.rowCount()
        self.findings_tbl.insertRow(row)
        vals = [f.name, f.owasp, f.confidence, f.point, f.evidence]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            if c == 2:
                item.setForeground(QColor(CONF_COLOR.get(f.confidence, theme.FG)))
            self.findings_tbl.setItem(row, c, item)

    def on_done(self):
        self.scan_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        n = len(self._findings)
        self.status.setText(f"done · {n} finding(s)")

    def show_finding(self):
        rows = self.findings_tbl.selectionModel().selectedRows()
        if not rows:
            return
        f = self._findings[rows[0].row()]
        self.req_view.set_text(f.request_text)
        self.resp_view.set_text(f.response_text)

    def export_findings(self):
        if not self._findings:
            self.status.setText("no findings to export"); return
        from PySide6.QtWidgets import QFileDialog
        from ..core import report
        path, flt = QFileDialog.getSaveFileName(
            self, "Export findings", "r3dproxy-findings.md",
            "Markdown (*.md);;JSON (*.json);;SARIF (*.sarif);;Evidence pack (folder) (*)")
        if not path:
            return
        try:
            tgt = self.current_target()
            target = f"{tgt.scheme}://{tgt.host}:{tgt.port}"
            low = (path + " " + flt).lower()
            if "evidence" in low:
                out = report.evidence_pack(self._findings, path.rsplit(".", 1)[0] + "_evidence", target)
                self.status.setText(f"evidence pack → {out}")
                return
            if path.endswith(".sarif") or "sarif" in flt.lower():
                data = report.findings_to_sarif(self._findings, target)
            elif path.endswith(".json") or "json" in flt.lower():
                data = report.findings_to_json(self._findings)
            else:
                data = report.findings_to_markdown(self._findings, target)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            self.status.setText(f"exported {len(self._findings)} findings → {path}")
        except Exception as e:
            self.status.setText(f"export failed: {e}")

    def _ctx_menu(self, pos):
        rows = self.findings_tbl.selectionModel().selectedRows()
        if not rows:
            return
        f = self._findings[rows[0].row()]
        menu = QMenu(self)
        a_rep = menu.addAction("Send request to Repeater")
        a_ai = menu.addAction("Send to AI Assistant")
        act = menu.exec(self.findings_tbl.viewport().mapToGlobal(pos))
        if act == a_rep:
            self.main.repeater_tab.new_tab(f.request_text, self.current_target())
            self.main.tabs.setCurrentWidget(self.main.repeater_tab)
        elif act == a_ai:
            self.main.send_to_ai(f.request_text, f.response_text)
