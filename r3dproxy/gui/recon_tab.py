"""Recon tab: drive external Linux tools — scanners (active/passive), directory
fuzzing, and subdomain discovery — with live output and a tool installer."""
from __future__ import annotations
import re
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QComboBox, QPushButton, QPlainTextEdit, QTabWidget,
                               QGroupBox, QFileDialog, QListWidget, QDialog,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QAbstractItemView, QMessageBox)
from PySide6.QtGui import QColor

from . import theme
from .workers import ProcessWorker
from ..core import exttools as X
from ..core import wordlists as wl


def _script_path():
    try:
        p = Path(__file__).resolve().parents[2] / "scripts" / "install_tools.sh"
        if p.exists():
            return p
    except Exception:
        pass
    return None


class _Runner(QWidget):
    """A console with Run/Stop wired to a ProcessWorker."""
    def __init__(self):
        super().__init__()
        self.worker = None
        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
        self.console.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")

    def run_argv(self, argv, on_line=None, on_done=None, record_fn=None):
        self.console.appendPlainText(f"$ {' '.join(argv)}\n")
        self._buf = []
        self.worker = ProcessWorker(argv)
        def line(l):
            self.console.appendPlainText(l)
            self._buf.append(l)
            if on_line:
                on_line(l)
        self.worker.line.connect(line)
        def done(rc):
            self.console.appendPlainText(f"\n[finished, exit {rc}]\n")
            if record_fn:
                try:
                    record_fn("\n".join(self._buf))
                except Exception:
                    pass
            if on_done:
                on_done(rc)
        self.worker.done.connect(done)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()


def _tool_combo(category):
    combo = QComboBox()
    for t in X.by_category(category):
        ok = t.installed()
        tag = "" if ok else "  (not installed)"
        mode = f" [{t.mode}]" if t.mode else ""
        combo.addItem(f"{t.name}{mode} — {t.desc}{tag}", t.id)
    return combo


class ScannersWidget(QWidget):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Target (host or URL):"))
        self.target = QLineEdit(); self.target.setPlaceholderText("https://target.com  or  target.com")
        row.addWidget(self.target, 1)
        v.addLayout(row)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Tool:"))
        self.combo = _tool_combo(X.SCANNER)
        row2.addWidget(self.combo, 1)
        row2.addWidget(QLabel("extra args:"))
        self.extra = QLineEdit(); self.extra.setMaximumWidth(220)
        row2.addWidget(self.extra)
        self.run_btn = QPushButton("Run"); self.run_btn.setObjectName("accent"); self.run_btn.clicked.connect(self.run)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.clicked.connect(self.stop)
        row2.addWidget(self.stop_btn); row2.addWidget(self.run_btn)
        v.addLayout(row2)
        self.runner = _Runner()
        v.addWidget(self.runner.console, 1)

    def run(self):
        if not self.target.text().strip():
            self.runner.console.appendPlainText("[set a target]"); return
        tid = self.combo.currentData()
        tool = X.get(tid)
        if not tool.installed():
            self.runner.console.appendPlainText(f"[{tool.name} not installed — {tool.install}]"); return
        ctx = X.RunCtx(target=self.target.text().strip(), extra=self.extra.text())
        self.runner.run_argv(
            X.build(tid, ctx),
            record_fn=lambda out: self.ctx.engagement.add_run(tool.name, "scanner", ctx.target, out))

    def stop(self):
        self.runner.stop()


class FuzzWidget(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Target URL:"))
        self.target = QLineEdit(); self.target.setPlaceholderText("http://target.com/FUZZ  (or http://target.com — /FUZZ is appended)")
        row.addWidget(self.target, 1)
        v.addLayout(row)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Tool:"))
        self.combo = _tool_combo(X.FUZZER)
        row2.addWidget(self.combo, 1)
        v.addLayout(row2)
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Wordlist:"))
        self.wl_combo = QComboBox()
        for n in wl.list_names():
            self.wl_combo.addItem(n.replace("builtin:", "★ ").replace("user:", "◆ "), n)
        idx = self.wl_combo.findData("builtin:paths-common")
        if idx >= 0:
            self.wl_combo.setCurrentIndex(idx)
        row3.addWidget(self.wl_combo, 1)
        self.file_edit = QLineEdit(); self.file_edit.setPlaceholderText("…or a wordlist file path")
        browse = QPushButton("Browse…"); browse.clicked.connect(self.browse)
        row3.addWidget(self.file_edit, 1); row3.addWidget(browse)
        v.addLayout(row3)
        row4 = QHBoxLayout()
        row4.addWidget(QLabel("extra args:"))
        self.extra = QLineEdit()
        row4.addWidget(self.extra, 1)
        self.run_btn = QPushButton("Run"); self.run_btn.setObjectName("accent"); self.run_btn.clicked.connect(self.run)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.clicked.connect(self.stop)
        row4.addWidget(self.stop_btn); row4.addWidget(self.run_btn)
        v.addLayout(row4)
        self.runner = _Runner()
        v.addWidget(self.runner.console, 1)

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Wordlist", "", "Text (*.txt *.lst);;All (*)")
        if path:
            self.file_edit.setText(path)

    def run(self):
        if not self.target.text().strip():
            self.runner.console.appendPlainText("[set a target URL]"); return
        tid = self.combo.currentData()
        tool = X.get(tid)
        if not tool.installed():
            self.runner.console.appendPlainText(f"[{tool.name} not installed — {tool.install}]"); return
        wordlist = self.file_edit.text().strip() or wl.materialize(self.wl_combo.currentData())
        ctx = X.RunCtx(target=self.target.text().strip(), wordlist=wordlist, extra=self.extra.text())
        self.runner.run_argv(
            X.build(tid, ctx),
            record_fn=lambda out: self.ctx.engagement.add_run(tool.name, "fuzzer", ctx.target, out))

    def stop(self):
        self.runner.stop()


class SubdomainWidget(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self._subs = set()
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Domain:"))
        self.domain = QLineEdit(); self.domain.setPlaceholderText("target.com")
        row.addWidget(self.domain, 1)
        row.addWidget(QLabel("Tool:"))
        self.combo = _tool_combo(X.SUBDOMAIN)
        row.addWidget(self.combo, 1)
        self.run_btn = QPushButton("Run"); self.run_btn.setObjectName("accent"); self.run_btn.clicked.connect(self.run)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.clicked.connect(self.stop)
        row.addWidget(self.stop_btn); row.addWidget(self.run_btn)
        v.addLayout(row)

        from PySide6.QtWidgets import QSplitter
        split = QSplitter(Qt.Horizontal)
        self.runner = _Runner()
        split.addWidget(self.runner.console)
        right = QWidget(); rv = QVBoxLayout(right)
        self.count_lbl = QLabel("0 subdomains")
        rv.addWidget(self.count_lbl)
        self.list = QListWidget()
        rv.addWidget(self.list, 1)
        addscope = QPushButton("Add all to scope"); addscope.clicked.connect(self.add_scope)
        rv.addWidget(addscope)
        split.addWidget(right)
        split.setSizes([620, 360])
        v.addWidget(split, 1)

    def run(self):
        dom = self.domain.text().strip()
        if not dom:
            self.runner.console.appendPlainText("[set a domain]"); return
        tid = self.combo.currentData()
        tool = X.get(tid)
        if not tool.installed():
            self.runner.console.appendPlainText(f"[{tool.name} not installed — {tool.install}]"); return
        self._subs.clear(); self.list.clear(); self.count_lbl.setText("0 subdomains")
        self._rx = re.compile(r"([a-z0-9_-]+\.)+" + re.escape(dom), re.I)
        self.runner.run_argv(
            X.build(tid, X.RunCtx(domain=dom)), on_line=self._on_line,
            record_fn=lambda out: (self.ctx.engagement.add_subdomains(self._subs),
                                   self.ctx.engagement.add_run(tool.name, "subdomain", dom, out)))

    def _on_line(self, line):
        for m in self._rx.findall(line) if False else self._rx.finditer(line):
            sub = m.group(0).lower()
            if sub not in self._subs:
                self._subs.add(sub)
                self.list.addItem(sub)
        self.count_lbl.setText(f"{len(self._subs)} subdomains")

    def add_scope(self):
        scope = list(self.ctx.config.get("scope") or [])
        for s in sorted(self._subs):
            if s not in scope:
                scope.append(s)
        self.ctx.config["scope"] = scope
        self.ctx.config.save()
        self.count_lbl.setText(f"{len(self._subs)} subdomains · added to scope")

    def stop(self):
        self.runner.stop()


class InstallDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("External tools — status & install")
        self.resize(640, 560)
        v = QVBoxLayout(self)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Tool", "Installed", "Install hint"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        v.addWidget(self.table, 1)
        self.refresh()

        bar = QHBoxLayout()
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self.refresh)
        bar.addWidget(refresh); bar.addStretch(1)
        script = _script_path()
        if script:
            run_nosudo = QPushButton("Install go/pip tools (no sudo)")
            run_nosudo.clicked.connect(lambda: self._run_installer(["bash", str(script), "--nosudo"]))
            bar.addWidget(run_nosudo)
            copy_cmd = QPushButton("Copy full install command")
            copy_cmd.clicked.connect(lambda: self._copy(f"sudo bash {script}"))
            bar.addWidget(copy_cmd)
        v.addLayout(bar)
        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
        self.console.setMaximumHeight(160)
        self.console.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        v.addWidget(self.console)
        self._worker = None

    def refresh(self):
        self.table.setRowCount(0)
        for t, ok in X.status():
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f"{t.name} ({t.category})"))
            it = QTableWidgetItem("yes" if ok else "no")
            it.setForeground(QColor(theme.OK if ok else theme.ACCENT))
            self.table.setItem(row, 1, it)
            self.table.setItem(row, 2, QTableWidgetItem(t.install))

    def _copy(self, text):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        self.console.appendPlainText(f"copied: {text}")

    def _run_installer(self, argv):
        self.console.appendPlainText(f"$ {' '.join(argv)}")
        self._worker = ProcessWorker(argv)
        self._worker.line.connect(self.console.appendPlainText)
        self._worker.done.connect(lambda rc: (self.console.appendPlainText(f"[exit {rc}]"), self.refresh()))
        self._worker.start()


class ReconTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        v = QVBoxLayout(self)

        bar = QHBoxLayout()
        info = QLabel("Drives installed Linux tools. Authorized targets only.")
        info.setStyleSheet(f"color:{theme.FG_DIM};")
        self.status_lbl = QLabel("")
        check = QPushButton("Check tools"); check.clicked.connect(self.check)
        install = QPushButton("Install tools…"); install.clicked.connect(self.open_install)
        bar.addWidget(info); bar.addStretch(1); bar.addWidget(self.status_lbl)
        bar.addWidget(check); bar.addWidget(install)
        v.addLayout(bar)

        inner = QTabWidget()
        self.scanners = ScannersWidget(ctx)
        self.fuzz = FuzzWidget(ctx, main)
        self.subs = SubdomainWidget(ctx, main)
        inner.addTab(self.scanners, "Scanners (active/passive)")
        inner.addTab(self.fuzz, "Directory fuzzing")
        inner.addTab(self.subs, "Subdomain discovery")
        self.inner = inner
        v.addWidget(inner, 1)
        self.check()

    def check(self):
        installed = sum(1 for _, ok in X.status() if ok)
        total = len(X.TOOLS)
        self.status_lbl.setText(f"{installed}/{total} tools installed")
        # rebuild combos to reflect current install state
        for w, cat in ((self.scanners, X.SCANNER), (self.fuzz, X.FUZZER), (self.subs, X.SUBDOMAIN)):
            cur = w.combo.currentData()
            w.combo.clear()
            for t in X.by_category(cat):
                ok = t.installed()
                mode = f" [{t.mode}]" if t.mode else ""
                w.combo.addItem(f"{t.name}{mode} — {t.desc}" + ("" if ok else "  (not installed)"), t.id)
            i = w.combo.findData(cur)
            if i >= 0:
                w.combo.setCurrentIndex(i)

    def open_install(self):
        InstallDialog(self).exec()
        self.check()

    def load_target(self, url):
        self.scanners.target.setText(url)
        self.fuzz.target.setText(url)
        self.inner.setCurrentIndex(0)
