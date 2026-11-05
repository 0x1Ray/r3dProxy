"""Repeater: edit and resend an individual request, inspect the response.

Supports multiple sub-tabs, each with its own target and request/response.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLineEdit, QLabel, QCheckBox, QSpinBox,
                               QTabWidget, QComboBox)  # noqa: F401

from .editor import HttpEditor
from .workers import SendWorker
from ..core.sender import Target


class RepeaterSession(QWidget):
    def __init__(self, ctx, main, request_text="", target: Target = None):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None

        v = QVBoxLayout(self)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Target:"))
        self.scheme = QComboBox()
        self.scheme.addItems(["http", "https"])
        self.host = QLineEdit()
        self.host.setPlaceholderText("host")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(80)
        self.raw_chk = QCheckBox("raw socket")
        self.raw_chk.setToolTip("Send byte-exact over a raw socket (no header normalization)")
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("accent")
        self.send_btn.clicked.connect(self.send)
        self.ai_btn = QPushButton("→ AI")
        self.ai_btn.clicked.connect(self.to_ai)
        self.status_lbl = QLabel("")

        bar.addWidget(self.scheme)
        bar.addWidget(self.host, 2)
        bar.addWidget(QLabel(":"))
        bar.addWidget(self.port)
        bar.addStretch(1)
        bar.addWidget(self.status_lbl)
        bar.addWidget(self.raw_chk)
        bar.addWidget(self.ai_btn)
        bar.addWidget(self.send_btn)
        v.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        self.req_edit = HttpEditor(read_only=False)
        self.resp_view = HttpEditor(read_only=True)
        split.addWidget(self.req_edit)
        split.addWidget(self.resp_view)
        split.setSizes([640, 640])
        v.addWidget(split)

        if target:
            self.scheme.setCurrentText(target.scheme)
            self.host.setText(target.host)
            self.port.setValue(target.port)
        if request_text:
            self.req_edit.set_text(request_text)

        self.scheme.currentTextChanged.connect(self._sync_default_port)

    def _sync_default_port(self, scheme):
        if self.port.value() in (80, 443):
            self.port.setValue(443 if scheme == "https" else 80)

    def current_target(self):
        return Target(host=self.host.text().strip(),
                      port=self.port.value(),
                      tls=self.scheme.currentText() == "https")

    def send(self):
        tgt = self.current_target()
        if not tgt.host:
            self.status_lbl.setText("set a host")
            return
        self.send_btn.setEnabled(False)
        self.status_lbl.setText("sending…")
        opts = {
            "timeout": self.ctx.config["sender_timeout"],
            "verify": self.ctx.config["sender_verify_tls"],
            "follow_redirects": self.ctx.config["sender_follow_redirects"],
            "raw": self.raw_chk.isChecked(),
        }
        self.worker = SendWorker(self.req_edit.text(), tgt, opts)
        self.worker.done.connect(self.on_result)
        self.worker.start()

    def on_result(self, res):
        self.send_btn.setEnabled(True)
        if res.ok:
            self.status_lbl.setText(f"{res.status} {res.reason} · {res.length}B · {res.elapsed_ms}ms")
            self.resp_view.set_text(res.response_text)
        else:
            self.status_lbl.setText("error")
            self.resp_view.set_text(f"[send failed]\n{res.error}")

    def to_ai(self):
        self.main.send_to_ai(self.req_edit.text(), self.resp_view.text())


class RepeaterTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        v = QVBoxLayout(self)

        bar = QHBoxLayout()
        add_btn = QPushButton("+ New")
        add_btn.clicked.connect(lambda: self.new_tab("", None))
        close_btn = QPushButton("× Close current")
        close_btn.clicked.connect(self.close_current)
        bar.addWidget(add_btn)
        bar.addWidget(close_btn)
        bar.addStretch(1)
        v.addLayout(bar)

        self.inner = QTabWidget()
        self.inner.setTabsClosable(True)
        self.inner.tabCloseRequested.connect(self.inner.removeTab)
        v.addWidget(self.inner)

        self.new_tab("", None)

    def new_tab(self, request_text, target):
        s = RepeaterSession(self.ctx, self.main, request_text, target)
        n = self.inner.count() + 1
        title = target.host if target else f"req {n}"
        idx = self.inner.addTab(s, title[:18])
        self.inner.setCurrentIndex(idx)

    def close_current(self):
        i = self.inner.currentIndex()
        if i >= 0:
            self.inner.removeTab(i)

    def serialize_tabs(self):
        out = []
        for i in range(self.inner.count()):
            s = self.inner.widget(i)
            if isinstance(s, RepeaterSession):
                out.append({
                    "scheme": s.scheme.currentText(),
                    "host": s.host.text(),
                    "port": s.port.value(),
                    "request": s.req_edit.text(),
                    "response": s.resp_view.text(),
                })
        return out

    def restore_tabs(self, tabs):
        if not tabs:
            return
        while self.inner.count():
            self.inner.removeTab(0)
        for t in tabs:
            tgt = Target(host=t.get("host", ""), port=int(t.get("port", 80)),
                         tls=t.get("scheme", "http") == "https")
            s = RepeaterSession(self.ctx, self.main, t.get("request", ""), tgt)
            s.resp_view.set_text(t.get("response", ""))
            self.inner.addTab(s, (t.get("host") or "req")[:18])
        if self.inner.count() == 0:
            self.new_tab("", None)
