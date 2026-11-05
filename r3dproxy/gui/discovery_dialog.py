"""Content discovery: brute-force hidden paths on a host with a wordlist.

Includes soft-404 calibration (probes a random path first) so pages that return
200 for everything don't flood the results. Found paths can be pushed into the
site map.
"""
from __future__ import annotations
import concurrent.futures
import uuid

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QComboBox, QSpinBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QPlainTextEdit, QGroupBox)

from . import theme
from ..core import wordlists as wl
from ..core import sender as sender_mod
from ..core.sender import Target


def _candidates(words, extensions):
    seen = set()
    out = []
    for w in words:
        w = w.strip().strip("/")
        if not w:
            continue
        for ext in extensions:
            cand = w + ext
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


class DiscoveryWorker(QThread):
    hit = Signal(str, int, int)        # path, status, length
    progress = Signal(int, int)
    done = Signal()

    def __init__(self, target, base_path, candidates, opts, threads=10):
        super().__init__()
        self.target = target
        self.base_path = base_path
        self.candidates = candidates
        self.opts = opts
        self.threads = threads
        self._stop = False
        self.soft404 = None   # (status, approx_len)

    def stop(self):
        self._stop = True

    def _req(self, path):
        full = "/" + (self.base_path.strip("/") + "/" if self.base_path.strip("/") else "") + path
        req = f"GET {full} HTTP/1.1\r\nHost: {self.target.host}\r\nUser-Agent: r3dProxy\r\nConnection: close\r\n\r\n"
        res = sender_mod.send(req, self.target,
                              timeout=self.opts.get("timeout", 15),
                              verify=self.opts.get("verify", False))
        return full, res

    def run(self):
        # calibrate soft-404
        rand = "r3d404" + uuid.uuid4().hex[:10]
        try:
            _f, r = self._req(rand)
            if r.ok:
                self.soft404 = (r.status, r.length)
        except Exception:
            pass
        total = len(self.candidates)
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._req, c): c for c in self.candidates}
            for fut in concurrent.futures.as_completed(futs):
                if self._stop:
                    break
                done += 1
                self.progress.emit(done, total)
                try:
                    full, res = fut.result()
                except Exception:
                    continue
                if not res.ok or res.status is None:
                    continue
                if res.status == 404:
                    continue
                if self.soft404 and res.status == self.soft404[0] and abs(res.length - self.soft404[1]) <= 32:
                    continue  # looks like the soft-404 page
                self.hit.emit(full, res.status, res.length)
        self.done.emit()


class ContentDiscoveryDialog(QDialog):
    def __init__(self, ctx, main, target: Target, base_path="", parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.main = main
        self.target = target
        self.worker = None
        self.setWindowTitle(f"Content discovery — {target.base()}")
        self.resize(720, 620)

        v = QVBoxLayout(self)
        cfg = QGroupBox("Configuration")
        cv = QVBoxLayout(cfg)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Base:"))
        self.base_lbl = QLineEdit(target.base() + ("/" + base_path.strip("/") if base_path.strip("/") else ""))
        self.base_lbl.setReadOnly(True)
        r1.addWidget(self.base_lbl, 1)
        cv.addLayout(r1)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Wordlist:"))
        self.wl_combo = QComboBox()
        for n in wl.list_names():
            self.wl_combo.addItem(n.replace("builtin:", "★ ").replace("user:", "◆ "), n)
        # default to paths-common if present
        idx = self.wl_combo.findData("builtin:paths-common")
        if idx >= 0:
            self.wl_combo.setCurrentIndex(idx)
        r2.addWidget(self.wl_combo, 1)
        r2.addWidget(QLabel("Extensions:"))
        self.exts = QLineEdit("'' , / , .php , .bak , .txt , .json")
        self.exts.setToolTip("comma-separated; '' means no extension, / means directory")
        r2.addWidget(self.exts, 1)
        cv.addLayout(r2)
        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Threads:"))
        self.threads = QSpinBox(); self.threads.setRange(1, 30); self.threads.setValue(10)
        r3.addWidget(self.threads)
        r3.addStretch(1)
        self.start_btn = QPushButton("Start"); self.start_btn.setObjectName("accent"); self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop)
        r3.addWidget(self.stop_btn); r3.addWidget(self.start_btn)
        cv.addLayout(r3)
        v.addWidget(cfg)

        self.progress = QLabel("idle"); v.addWidget(self.progress)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Path", "Status", "Length"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        v.addWidget(self.table, 1)

        bar = QHBoxLayout()
        add_map = QPushButton("Add found to site map"); add_map.clicked.connect(self.add_to_map)
        bar.addStretch(1); bar.addWidget(add_map)
        close = QPushButton("Close"); close.clicked.connect(self.accept)
        bar.addWidget(close)
        v.addLayout(bar)
        self._found = []

    def _parse_exts(self):
        raw = self.exts.text().split(",")
        out = []
        for e in raw:
            e = e.strip().strip("'\"")
            if e in ("", "''"):
                out.append("")
            else:
                out.append(e)
        return out or [""]

    def start(self):
        words = wl.load(self.wl_combo.currentData())
        if not words:
            self.progress.setText("empty wordlist"); return
        cands = _candidates(words, self._parse_exts())
        self.table.setRowCount(0); self._found = []
        self.table.setSortingEnabled(False)
        opts = {"timeout": self.ctx.config["sender_timeout"],
                "verify": self.ctx.config["sender_verify_tls"]}
        base_path = ""
        self.worker = DiscoveryWorker(self.target, base_path, cands, opts, self.threads.value())
        self.worker.hit.connect(self.on_hit)
        self.worker.progress.connect(lambda d, t: self.progress.setText(f"{d}/{t} tested · {len(self._found)} found"))
        self.worker.done.connect(self.on_done)
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()

    def on_hit(self, path, status, length):
        self._found.append((path, status, length))
        row = self.table.rowCount(); self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(path))
        s = QTableWidgetItem(str(status));
        c = theme.OK if 200 <= status < 300 else (theme.WARN if 300 <= status < 400 else theme.FG)
        from PySide6.QtGui import QColor
        s.setForeground(QColor(c))
        self.table.setItem(row, 1, s)
        self.table.setItem(row, 2, QTableWidgetItem(str(length)))

    def on_done(self):
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.table.setSortingEnabled(True)
        self.progress.setText(f"done · {len(self._found)} found")

    def add_to_map(self):
        from ..core.flowstore import FlowRecord
        import time
        if hasattr(self.ctx, "engagement"):
            self.ctx.engagement.add_discovered(
                [(f"{self.target.base()}{p}", s, l) for p, s, l in self._found])
        for path, status, length in self._found:
            url = f"{self.target.base()}{path}"
            fid = "disc-" + uuid.uuid4().hex[:10]
            self.ctx.store.add(FlowRecord(
                fid=fid, method="GET", host=self.target.host, url=url,
                scheme=self.target.scheme, status=status, length=length,
                request_text=f"GET {path} HTTP/1.1\r\nHost: {self.target.host}\r\n\r\n",
                response_text=""))
        if hasattr(self.main, "target_tab"):
            self.main.target_tab.rebuild()
        if hasattr(self.main, "proxy_tab"):
            self.main.proxy_tab.rebuild_from_store()
        self.progress.setText(f"added {len(self._found)} paths to site map")
