"""OAST tab: run the callback listener, generate token URLs, watch for hits."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                               QLabel, QLineEdit, QSpinBox, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView,
                               QGroupBox, QPlainTextEdit)
from PySide6.QtGui import QColor

from . import theme
from ..core.oast import OASTBridge, OASTListener


class OASTTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.bridge = OASTBridge()
        self.listener = OASTListener(self.bridge)
        self.bridge.hit.connect(self.on_hit)
        self.bridge.started.connect(self.on_started)
        self.bridge.stopped.connect(self.on_stopped)

        v = QVBoxLayout(self)
        info = QLabel(
            "Out-of-band callback listener. Generate a token URL, put it in a payload "
            "(SSRF/XXE/blind RCE/SQLi); if the target's backend connects back, it shows "
            "below — proof of a blind vuln. For internet callbacks, run this where the "
            "target can reach it, or set a public base URL in Settings/interactsh.")
        info.setWordWrap(True); info.setStyleSheet(f"color:{theme.FG_DIM};")
        v.addWidget(info)

        ctl = QGroupBox("Listener")
        cv = QVBoxLayout(ctl)
        row = QHBoxLayout()
        row.addWidget(QLabel("Bind:"))
        self.host = QLineEdit("0.0.0.0"); self.host.setMaximumWidth(140)
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(9999)
        self.start_btn = QPushButton("Start"); self.start_btn.setObjectName("accent")
        self.start_btn.clicked.connect(self.toggle)
        self.state = QLabel("stopped"); self.state.setStyleSheet(f"color:{theme.FG_DIM};")
        row.addWidget(self.host); row.addWidget(QLabel(":")); row.addWidget(self.port)
        row.addWidget(self.start_btn); row.addWidget(self.state); row.addStretch(1)
        cv.addLayout(row)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Public base URL (optional):"))
        self.base = QLineEdit(self.ctx.config.get("oast_base", ""))
        self.base.setPlaceholderText("e.g. http://your-vps:9999  or  https://xxxx.oast.site")
        self.base.editingFinished.connect(self._save_base)
        row2.addWidget(self.base, 1)
        gen = QPushButton("Generate payload URL"); gen.clicked.connect(self.gen_url)
        row2.addWidget(gen)
        cv.addLayout(row2)
        self.gen_out = QLineEdit(); self.gen_out.setReadOnly(True)
        self.gen_out.setPlaceholderText("generated token URL appears here — copy into a payload")
        cv.addWidget(self.gen_out)
        v.addWidget(ctl)

        v.addWidget(QLabel("Callbacks received:"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Source IP", "Method", "Token", "Path"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_detail)
        v.addWidget(self.table, 2)
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True)
        self.detail.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        v.addWidget(self.detail, 1)
        self._hits = []

    def _save_base(self):
        self.ctx.config["oast_base"] = self.base.text().strip()
        self.ctx.config.save()

    def toggle(self):
        if self.listener.running:
            self.listener.stop()
        else:
            try:
                self.listener.start(self.host.text().strip() or "0.0.0.0", self.port.value())
            except Exception as e:
                self.state.setText(f"error: {e}")
                self.state.setStyleSheet(f"color:{theme.ACCENT};")

    def on_started(self, host, port):
        self.state.setText(f"listening on {host}:{port}")
        self.state.setStyleSheet(f"color:{theme.OK};")
        self.start_btn.setText("Stop")

    def on_stopped(self):
        self.state.setText("stopped")
        self.state.setStyleSheet(f"color:{theme.FG_DIM};")
        self.start_btn.setText("Start")

    def gen_url(self):
        token = OASTListener.new_token()
        base = self.base.text().strip()
        if not base:
            base = f"http://{self.host.text().strip() or '127.0.0.1'}:{self.port.value()}"
        base = base.rstrip("/")
        self.gen_out.setText(f"{base}/{token}")

    def on_hit(self, info):
        self._hits.append(info)
        row = self.table.rowCount()
        self.table.insertRow(row)
        vals = [info["time"], info["src"], info["method"], info["token"], info["path"]]
        for c, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            if c == 0:
                item.setForeground(QColor(theme.OK))
            self.table.setItem(row, c, item)
        self.table.scrollToBottom()

    def show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        info = self._hits[rows[0].row()]
        lines = [f"{info['method']} {info['path']}", f"From: {info['src']}",
                 f"Token: {info['token']}", "", "Headers:"]
        for k, v in info.get("headers", {}).items():
            lines.append(f"  {k}: {v}")
        self.detail.setPlainText("\n".join(lines))
