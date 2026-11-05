"""Intruder-lite: sniper fuzzer over a single marked position (§payload§).

Mark one injection point with §...§ in the request, paste a payload list, and
run. Each payload is substituted in and sent; results (status, length, time)
land in a table. This is the fast way to test which variant of a rejected
payload gets through — and it pairs with the AI assistant's suggestions.
"""
from __future__ import annotations
import re

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QPlainTextEdit, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QGroupBox, QSpinBox, QComboBox, QLineEdit, QCheckBox,
                               QFileDialog, QInputDialog, QMessageBox)

from .editor import HttpEditor
from ..core import sender as sender_mod
from ..core import raw_sender as raw_sender_mod
from ..core import wordlists as wl
from ..core.sender import Target

MARKER = "§"


class IntruderWorker(QThread):
    result = Signal(int, str, object)   # index, payload, SendResult
    finished_all = Signal()

    def __init__(self, template, payloads, target, opts, delay_ms):
        super().__init__()
        self.template = template
        self.payloads = payloads
        self.target = target
        self.opts = opts
        self.delay_ms = delay_ms
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        mod = raw_sender_mod if self.opts.get("raw") else sender_mod
        for i, p in enumerate(self.payloads):
            if self._stop:
                break
            req = _substitute(self.template, p)
            res = mod.send(
                req, self.target,
                timeout=self.opts.get("timeout", 20),
                verify=self.opts.get("verify", False),
                follow_redirects=self.opts.get("follow_redirects", False),
            )
            self.result.emit(i, p, res)
            if self.delay_ms:
                self.msleep(self.delay_ms)
        self.finished_all.emit()


def _substitute(template, payload):
    # Replace the first §...§ region with the payload.
    return re.sub(rf"{MARKER}[^{MARKER}]*{MARKER}", lambda m: payload, template, count=1)


class IntruderTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None
        self.target = None
        self._responses = {}

        root = QVBoxLayout(self)
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split)

        # left: request template + payloads
        left = QWidget()
        lv = QVBoxLayout(left)

        tbar = QHBoxLayout()
        tbar.addWidget(QLabel("Target:"))
        self.scheme = QComboBox(); self.scheme.addItems(["http", "https"])
        self.host = QLineEdit(); self.host.setPlaceholderText("host")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(80)
        tbar.addWidget(self.scheme); tbar.addWidget(self.host, 2)
        tbar.addWidget(QLabel(":")); tbar.addWidget(self.port)
        lv.addLayout(tbar)

        lv.addWidget(QLabel("Request template — wrap the injection point in §…§:"))
        self.template_edit = HttpEditor(read_only=False)
        lv.addWidget(self.template_edit, 3)

        mbar = QHBoxLayout()
        mark_btn = QPushButton("Mark selection §§")
        mark_btn.clicked.connect(self.mark_selection)
        mbar.addWidget(mark_btn)
        mbar.addStretch(1)
        lv.addLayout(mbar)

        # Wordlist manager row.
        wbar = QHBoxLayout()
        wbar.addWidget(QLabel("Wordlist:"))
        self.wl_combo = QComboBox()
        self.wl_combo.setMinimumWidth(160)
        wbar.addWidget(self.wl_combo, 1)
        self.wl_replace = QPushButton("Load")
        self.wl_replace.setToolTip("Replace the payload box with this wordlist")
        self.wl_replace.clicked.connect(lambda: self.load_wordlist(replace=True))
        self.wl_append = QPushButton("Append")
        self.wl_append.setToolTip("Append this wordlist to the payload box")
        self.wl_append.clicked.connect(lambda: self.load_wordlist(replace=False))
        wl_import = QPushButton("Import…")
        wl_import.setToolTip("Import a .txt wordlist into ~/.r3dproxy/wordlists/")
        wl_import.clicked.connect(self.import_wordlist)
        wl_save = QPushButton("Save as…")
        wl_save.setToolTip("Save the payload box as a reusable user wordlist")
        wl_save.clicked.connect(self.save_wordlist)
        wl_refresh = QPushButton("⟳")
        wl_refresh.setToolTip("Reload the wordlist folder")
        wl_refresh.setMaximumWidth(34)
        wl_refresh.clicked.connect(self.refresh_wordlists)
        for b in (self.wl_replace, self.wl_append, wl_import, wl_save, wl_refresh):
            wbar.addWidget(b)
        lv.addLayout(wbar)

        lv.addWidget(QLabel("Payloads (one per line):"))
        self.payloads_edit = QPlainTextEdit()
        self.payloads_edit.setPlaceholderText("' OR '1'='1\n<script>alert(1)</script>\n../../../../etc/passwd")
        lv.addWidget(self.payloads_edit, 2)
        self.refresh_wordlists()

        rbar = QHBoxLayout()
        rbar.addWidget(QLabel("delay ms:"))
        self.delay = QSpinBox(); self.delay.setRange(0, 10000); self.delay.setValue(0)
        rbar.addWidget(self.delay)
        self.raw_chk = QCheckBox("raw socket")
        rbar.addWidget(self.raw_chk)
        rbar.addStretch(1)
        self.start_btn = QPushButton("Start attack"); self.start_btn.setObjectName("accent")
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        rbar.addWidget(self.stop_btn); rbar.addWidget(self.start_btn)
        lv.addLayout(rbar)
        split.addWidget(left)

        # right: results
        right = QWidget()
        rv = QVBoxLayout(right)
        self.progress = QLabel("idle")
        rv.addWidget(self.progress)
        self.results = QTableWidget(0, 5)
        self.results.setHorizontalHeaderLabels(["#", "Payload", "Status", "Len", "ms"])
        self.results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results.itemSelectionChanged.connect(self.show_selected)
        rv.addWidget(self.results, 2)
        self.resp_view = HttpEditor(read_only=True)
        rv.addWidget(self.resp_view, 2)
        split.addWidget(right)
        split.setSizes([620, 660])

    # -------- wordlists --------
    def refresh_wordlists(self):
        current = self.wl_combo.currentData()
        self.wl_combo.clear()
        for name in wl.list_names():
            label = name.replace("builtin:", "★ ").replace("user:", "◆ ")
            self.wl_combo.addItem(label, name)
        # try to restore selection
        if current:
            idx = self.wl_combo.findData(current)
            if idx >= 0:
                self.wl_combo.setCurrentIndex(idx)

    def load_wordlist(self, replace):
        name = self.wl_combo.currentData()
        if not name:
            return
        payloads = wl.load(name)
        if not payloads:
            self.progress.setText(f"{name} is empty")
            return
        existing = self.payloads_edit.toPlainText()
        if replace or not existing.strip():
            self.payloads_edit.setPlainText("\n".join(payloads))
        else:
            self.payloads_edit.setPlainText(existing.rstrip("\n") + "\n" + "\n".join(payloads))

    def import_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import wordlist", "",
                                              "Text files (*.txt *.lst);;All files (*)")
        if not path:
            return
        try:
            new_name = wl.import_file(path)
            self.refresh_wordlists()
            idx = self.wl_combo.findData(new_name)
            if idx >= 0:
                self.wl_combo.setCurrentIndex(idx)
            self.progress.setText(f"imported {new_name}")
        except Exception as e:
            QMessageBox.warning(self, "Import failed", str(e))

    def save_wordlist(self):
        payloads = [p for p in self.payloads_edit.toPlainText().splitlines() if p != ""]
        if not payloads:
            self.progress.setText("nothing to save"); return
        name, ok = QInputDialog.getText(self, "Save wordlist", "Name:")
        if ok and name.strip():
            new_name = wl.save_user(name.strip(), payloads)
            self.refresh_wordlists()
            idx = self.wl_combo.findData(new_name)
            if idx >= 0:
                self.wl_combo.setCurrentIndex(idx)
            self.progress.setText(f"saved {new_name}")

    def load(self, request_text, target: Target):
        self.target = target
        self.template_edit.set_text(request_text)
        self.scheme.setCurrentText(target.scheme)
        self.host.setText(target.host)
        self.port.setValue(target.port)

    def set_payloads(self, payloads):
        self.payloads_edit.setPlainText("\n".join(payloads))

    def load_request_and_payloads(self, request_text, payloads):
        self.template_edit.set_text(request_text)
        from ..core.httptext import split_message
        _s, headers, _b = split_message(request_text)
        for k, v in headers:
            if k.lower() == "host":
                host = v.strip()
                port = self.port.value()
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    if p.isdigit():
                        host, port = h, int(p)
                self.host.setText(host)
                self.port.setValue(port)
                break
        self.set_payloads(payloads)

    def mark_selection(self):
        cur = self.template_edit.textCursor()
        sel = cur.selectedText()
        if sel:
            cur.insertText(f"{MARKER}{sel}{MARKER}")

    def current_target(self):
        return Target(host=self.host.text().strip(), port=self.port.value(),
                      tls=self.scheme.currentText() == "https")

    def start(self):
        tgt = self.current_target()
        if not tgt.host:
            self.progress.setText("set a host"); return
        template = self.template_edit.text()
        if MARKER not in template:
            self.progress.setText("no injection marker — select text and click 'Mark selection §§'")
            return
        payloads = [p for p in self.payloads_edit.toPlainText().splitlines() if p != ""]
        if not payloads:
            self.progress.setText("no payloads"); return

        self.results.setRowCount(0)
        self._responses.clear()
        self.resp_view.set_text("")
        opts = {
            "timeout": self.ctx.config["sender_timeout"],
            "verify": self.ctx.config["sender_verify_tls"],
            "follow_redirects": self.ctx.config["sender_follow_redirects"],
            "raw": self.raw_chk.isChecked(),
        }
        self.worker = IntruderWorker(template, payloads, tgt, opts, self.delay.value())
        self.worker.result.connect(self.on_result)
        self.worker.finished_all.connect(self.on_finished)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._total = len(payloads)
        self.progress.setText(f"running 0/{self._total}")
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()

    def on_result(self, idx, payload, res):
        row = self.results.rowCount()
        self.results.insertRow(row)
        vals = [str(idx + 1), payload,
                ("ERR" if not res.ok else str(res.status)),
                str(res.length), str(res.elapsed_ms)]
        for c, val in enumerate(vals):
            self.results.setItem(row, c, QTableWidgetItem(val))
        self._responses[row] = (payload, res)
        self.progress.setText(f"running {row + 1}/{self._total}")

    def on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setText(f"done · {self.results.rowCount()} requests")

    def show_selected(self):
        rows = self.results.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        data = self._responses.get(row)
        if data:
            payload, res = data
            if res.ok:
                self.resp_view.set_text(res.response_text)
            else:
                self.resp_view.set_text(f"[send failed]\n{res.error}")
