"""Intruder: Burp-style fuzzer with 4 attack types, multi-position payload sets,
wordlists, grep-extract and sortable results."""
from __future__ import annotations

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
from ..core import intruder as intr
from ..core.sender import Target

MARKER = intr.MARKER
ATTACK_LABELS = {
    intr.SNIPER: "Sniper (1 set, one position at a time)",
    intr.BATTERING_RAM: "Battering ram (1 set, all positions same)",
    intr.PITCHFORK: "Pitchfork (set per position, lockstep)",
    intr.CLUSTER_BOMB: "Cluster bomb (set per position, all combos)",
}


class _NumItem(QTableWidgetItem):
    """Table item that sorts numerically."""
    def __init__(self, value):
        super().__init__(str(value))
        try:
            self._v = float(value)
        except (TypeError, ValueError):
            self._v = float("inf")
    def __lt__(self, other):
        if isinstance(other, _NumItem):
            return self._v < other._v
        return super().__lt__(other)


class IntruderWorker(QThread):
    result = Signal(int, tuple, object, str)   # index, labels, SendResult, extract
    finished_all = Signal()

    def __init__(self, template, attack, sets, target, opts, delay_ms, grep):
        super().__init__()
        self.template = template
        self.attack = attack
        self.sets = sets
        self.target = target
        self.opts = opts
        self.delay_ms = delay_ms
        self.grep = grep
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        mod = raw_sender_mod if self.opts.get("raw") else sender_mod
        for i, job in enumerate(intr.generate(self.template, self.attack, self.sets)):
            if self._stop:
                break
            res = mod.send(job.request_text, self.target,
                           timeout=self.opts.get("timeout", 20),
                           verify=self.opts.get("verify", False),
                           follow_redirects=self.opts.get("follow_redirects", False))
            extract = intr.grep_extract(res.response_text, self.grep) if (res.ok and self.grep) else ""
            self.result.emit(i, job.labels, res, extract)
            if self.delay_ms:
                self.msleep(self.delay_ms)
        self.finished_all.emit()


class IntruderTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None
        self.target = None
        self._responses = []     # list of (labels, SendResult)
        self._sets = {}          # position index -> payloads text
        self._cur_pos = 0

        root = QVBoxLayout(self)
        split = QSplitter(Qt.Horizontal)
        root.addWidget(split)

        # ---------- left: request + config ----------
        left = QWidget(); lv = QVBoxLayout(left)

        tbar = QHBoxLayout()
        tbar.addWidget(QLabel("Target:"))
        self.scheme = QComboBox(); self.scheme.addItems(["http", "https"])
        self.host = QLineEdit(); self.host.setPlaceholderText("host")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(80)
        tbar.addWidget(self.scheme); tbar.addWidget(self.host, 2)
        tbar.addWidget(QLabel(":")); tbar.addWidget(self.port)
        lv.addLayout(tbar)

        abar = QHBoxLayout()
        abar.addWidget(QLabel("Attack:"))
        self.attack = QComboBox()
        for at in intr.ATTACK_TYPES:
            self.attack.addItem(ATTACK_LABELS[at], at)
        self.attack.currentIndexChanged.connect(self._on_attack_changed)
        abar.addWidget(self.attack, 1)
        lv.addLayout(abar)

        lv.addWidget(QLabel("Request template — wrap each injection point in §…§:"))
        self.template_edit = HttpEditor(read_only=False)
        lv.addWidget(self.template_edit, 3)
        mbar = QHBoxLayout()
        mark_btn = QPushButton("Mark selection §§"); mark_btn.clicked.connect(self.mark_selection)
        refresh_pos = QPushButton("Refresh positions"); refresh_pos.clicked.connect(self.refresh_positions)
        self.pos_info = QLabel("0 positions")
        mbar.addWidget(mark_btn); mbar.addWidget(refresh_pos); mbar.addWidget(self.pos_info); mbar.addStretch(1)
        lv.addLayout(mbar)

        # payload set selector (per position for pitchfork/cluster bomb)
        psel = QHBoxLayout()
        psel.addWidget(QLabel("Payload set:"))
        self.pos_combo = QComboBox(); self.pos_combo.currentIndexChanged.connect(self._on_pos_changed)
        psel.addWidget(self.pos_combo, 1)
        lv.addLayout(psel)

        # wordlist manager
        wbar = QHBoxLayout()
        wbar.addWidget(QLabel("Wordlist:"))
        self.wl_combo = QComboBox(); self.wl_combo.setMinimumWidth(140)
        wbar.addWidget(self.wl_combo, 1)
        b_load = QPushButton("Load"); b_load.clicked.connect(lambda: self.load_wordlist(True))
        b_app = QPushButton("Append"); b_app.clicked.connect(lambda: self.load_wordlist(False))
        b_imp = QPushButton("Import…"); b_imp.clicked.connect(self.import_wordlist)
        b_sav = QPushButton("Save as…"); b_sav.clicked.connect(self.save_wordlist)
        b_ref = QPushButton("⟳"); b_ref.setMaximumWidth(34); b_ref.clicked.connect(self.refresh_wordlists)
        for b in (b_load, b_app, b_imp, b_sav, b_ref):
            wbar.addWidget(b)
        lv.addLayout(wbar)

        self.payloads_edit = QPlainTextEdit()
        self.payloads_edit.setPlaceholderText("payloads for the selected set, one per line")
        lv.addWidget(self.payloads_edit, 2)

        gbar = QHBoxLayout()
        gbar.addWidget(QLabel("Grep-extract (regex):"))
        self.grep = QLineEdit(); self.grep.setPlaceholderText(r"e.g. <title>(.*?)</title>  or  \"balance\":(\d+)")
        gbar.addWidget(self.grep, 1)
        lv.addLayout(gbar)

        rbar = QHBoxLayout()
        rbar.addWidget(QLabel("delay ms:"))
        self.delay = QSpinBox(); self.delay.setRange(0, 10000); self.delay.setValue(0)
        rbar.addWidget(self.delay)
        self.raw_chk = QCheckBox("raw socket"); rbar.addWidget(self.raw_chk)
        rbar.addStretch(1)
        self.start_btn = QPushButton("Start attack"); self.start_btn.setObjectName("accent")
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop)
        rbar.addWidget(self.stop_btn); rbar.addWidget(self.start_btn)
        lv.addLayout(rbar)
        split.addWidget(left)

        # ---------- right: results ----------
        right = QWidget(); rv = QVBoxLayout(right)
        self.progress = QLabel("idle")
        rv.addWidget(self.progress)
        self.results = QTableWidget(0, 5)
        self.results.setHorizontalHeaderLabels(["#", "Payload(s)", "Status", "Len", "ms"])
        self.results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results.setSortingEnabled(True)
        self.results.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results.itemSelectionChanged.connect(self.show_selected)
        rv.addWidget(self.results, 2)
        self.resp_view = HttpEditor(read_only=True)
        rv.addWidget(self.resp_view, 2)
        split.addWidget(right)
        split.setSizes([640, 640])

        self._grep_in_table = False
        self.refresh_wordlists()
        self._on_attack_changed()

    # ---------- attack type / positions ----------
    def _on_attack_changed(self):
        at = self.attack.currentData()
        multi = at in (intr.PITCHFORK, intr.CLUSTER_BOMB)
        self.pos_combo.setEnabled(multi)
        self.refresh_positions()

    def refresh_positions(self):
        # persist current editor into the current set first
        self._store_current_set()
        seeds = intr.find_positions(self.template_edit.text())
        n = len(seeds)
        self.pos_info.setText(f"{n} position(s)")
        at = self.attack.currentData()
        self.pos_combo.blockSignals(True)
        self.pos_combo.clear()
        if at in (intr.PITCHFORK, intr.CLUSTER_BOMB) and n > 0:
            for i, s in enumerate(seeds):
                self.pos_combo.addItem(f"Position {i+1}  (§{s}§)", i)
        else:
            self.pos_combo.addItem("Set 1", 0)
        self.pos_combo.blockSignals(False)
        self._cur_pos = self.pos_combo.currentData() or 0
        self.payloads_edit.setPlainText(self._sets.get(self._cur_pos, ""))

    def _store_current_set(self):
        self._sets[self._cur_pos] = self.payloads_edit.toPlainText()

    def _on_pos_changed(self):
        self._store_current_set()
        self._cur_pos = self.pos_combo.currentData() or 0
        self.payloads_edit.setPlainText(self._sets.get(self._cur_pos, ""))

    # ---------- wordlists ----------
    def refresh_wordlists(self):
        current = self.wl_combo.currentData()
        self.wl_combo.clear()
        for name in wl.list_names():
            self.wl_combo.addItem(name.replace("builtin:", "★ ").replace("user:", "◆ "), name)
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
            self.progress.setText(f"{name} is empty"); return
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
            new = wl.import_file(path); self.refresh_wordlists()
            i = self.wl_combo.findData(new)
            if i >= 0: self.wl_combo.setCurrentIndex(i)
            self.progress.setText(f"imported {new}")
        except Exception as e:
            QMessageBox.warning(self, "Import failed", str(e))

    def save_wordlist(self):
        payloads = [p for p in self.payloads_edit.toPlainText().splitlines() if p != ""]
        if not payloads:
            self.progress.setText("nothing to save"); return
        name, ok = QInputDialog.getText(self, "Save wordlist", "Name:")
        if ok and name.strip():
            new = wl.save_user(name.strip(), payloads); self.refresh_wordlists()
            i = self.wl_combo.findData(new)
            if i >= 0: self.wl_combo.setCurrentIndex(i)
            self.progress.setText(f"saved {new}")

    # ---------- load from other tabs ----------
    def load(self, request_text, target: Target):
        self.target = target
        self.template_edit.set_text(request_text)
        self.scheme.setCurrentText(target.scheme)
        self.host.setText(target.host); self.port.setValue(target.port)
        self.refresh_positions()

    def set_payloads(self, payloads):
        self.payloads_edit.setPlainText("\n".join(payloads))
        self._store_current_set()

    def load_request_and_payloads(self, request_text, payloads):
        self.template_edit.set_text(request_text)
        from ..core.httptext import split_message
        _s, headers, _b = split_message(request_text)
        for k, v in headers:
            if k.lower() == "host":
                host = v.strip(); port = self.port.value()
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    if p.isdigit(): host, port = h, int(p)
                self.host.setText(host); self.port.setValue(port)
                break
        self.refresh_positions()
        self.set_payloads(payloads)

    def mark_selection(self):
        cur = self.template_edit.textCursor()
        if cur.selectedText():
            cur.insertText(f"{MARKER}{cur.selectedText()}{MARKER}")
            self.refresh_positions()

    def current_target(self):
        return Target(self.host.text().strip(), self.port.value(),
                      self.scheme.currentText() == "https")

    # ---------- run ----------
    def start(self):
        tgt = self.current_target()
        if not tgt.host:
            self.progress.setText("set a host"); return
        template = self.template_edit.text()
        if MARKER not in template:
            self.progress.setText("no injection marker — select text and 'Mark selection §§'"); return
        self._store_current_set()
        at = self.attack.currentData()
        n = intr.count_positions(template)
        # build payload sets
        if at in (intr.SNIPER, intr.BATTERING_RAM):
            sets = [[p for p in self._sets.get(0, "").splitlines() if p != ""]]
        else:
            sets = []
            for i in range(n):
                sets.append([p for p in self._sets.get(i, "").splitlines() if p != ""])
        total = intr.count_jobs(template, at, sets)
        if total == 0:
            self.progress.setText("no payloads (each position needs a set for pitchfork/cluster bomb)"); return

        self.results.setSortingEnabled(False)
        self.results.setRowCount(0)
        self._responses = []
        self.resp_view.set_text("")
        grep = self.grep.text().strip()
        # add extract column if grepping
        if grep and not self._grep_in_table:
            self.results.insertColumn(5)
            self.results.setHorizontalHeaderItem(5, QTableWidgetItem("Extract"))
            self._grep_in_table = True
        opts = {"timeout": self.ctx.config["sender_timeout"],
                "verify": self.ctx.config["sender_verify_tls"],
                "follow_redirects": self.ctx.config["sender_follow_redirects"],
                "raw": self.raw_chk.isChecked()}
        self.worker = IntruderWorker(template, at, sets, tgt, opts, self.delay.value(), grep)
        self.worker.result.connect(self.on_result)
        self.worker.finished_all.connect(self.on_finished)
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self._total = total
        self.progress.setText(f"running 0/{total}  ({at})")
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()

    def on_result(self, idx, labels, res, extract):
        li = len(self._responses)
        self._responses.append((labels, res))
        row = self.results.rowCount()
        self.results.insertRow(row)
        item0 = _NumItem(idx + 1)
        item0.setData(Qt.UserRole, li)   # survives sorting
        self.results.setItem(row, 0, item0)
        self.results.setItem(row, 1, QTableWidgetItem(" | ".join(labels)))
        self.results.setItem(row, 2, _NumItem("ERR" if not res.ok else res.status))
        self.results.setItem(row, 3, _NumItem(res.length))
        self.results.setItem(row, 4, _NumItem(res.elapsed_ms))
        if self._grep_in_table:
            self.results.setItem(row, 5, QTableWidgetItem(extract))
        self.progress.setText(f"running {self.results.rowCount()}/{self._total}")

    def on_finished(self):
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.results.setSortingEnabled(True)
        self.progress.setText(f"done · {self.results.rowCount()} requests")

    def show_selected(self):
        rows = self.results.selectionModel().selectedRows()
        if not rows:
            return
        item0 = self.results.item(rows[0].row(), 0)
        if item0 is None:
            return
        li = item0.data(Qt.UserRole)
        if li is None or li >= len(self._responses):
            return
        labels, res = self._responses[li]
        self.resp_view.set_text(res.response_text if res.ok else f"[send failed]\n{res.error}")
