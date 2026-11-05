"""AI Assistant: feed a request + response to Claude and get a diagnosis of why
a payload/input was rejected, plus concrete modified requests to try."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QLineEdit, QTextBrowser,
                               QGroupBox)

from .editor import HttpEditor
from .workers import AIWorker, AIPayloadWorker


class AITab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None

        root = QVBoxLayout(self)

        info = QLabel(
            "Paste or send a request/response here. The assistant explains why the "
            "input/payload was likely rejected and proposes variants to try. "
            "For use on targets you are authorized to test.")
        info.setWordWrap(True)
        info.setStyleSheet("color:#8b9096;")
        root.addWidget(info)

        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        left = QWidget()
        lv = QVBoxLayout(left)
        io = QSplitter(Qt.Vertical)
        reqbox = QGroupBox("Request")
        rl = QVBoxLayout(reqbox)
        self.req_edit = HttpEditor(read_only=False)
        rl.addWidget(self.req_edit)
        respbox = QGroupBox("Response")
        sl = QVBoxLayout(respbox)
        self.resp_edit = HttpEditor(read_only=False)
        sl.addWidget(self.resp_edit)
        io.addWidget(reqbox)
        io.addWidget(respbox)
        io.setSizes([300, 300])
        lv.addWidget(io, 1)

        nbar = QHBoxLayout()
        nbar.addWidget(QLabel("Note:"))
        self.note = QLineEdit()
        self.note.setPlaceholderText("e.g. payload got 403, WAF suspected / input field rejects quotes")
        nbar.addWidget(self.note, 1)
        self.payloads_btn = QPushButton("Payloads → Intruder")
        self.payloads_btn.setToolTip("Ask the AI for bypass payloads and load them into Intruder")
        self.payloads_btn.clicked.connect(self.gen_payloads)
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setObjectName("accent")
        self.analyze_btn.clicked.connect(self.analyze)
        nbar.addWidget(self.payloads_btn)
        nbar.addWidget(self.analyze_btn)
        lv.addLayout(nbar)
        split.addWidget(left)

        right = QGroupBox("Analysis & suggested payloads")
        rv = QVBoxLayout(right)
        self.output = QTextBrowser()
        self.output.setOpenExternalLinks(True)
        self.output.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        rv.addWidget(self.output)
        split.addWidget(right)
        split.setSizes([620, 660])

    def load(self, req_text, resp_text):
        self.req_edit.set_text(req_text or "")
        self.resp_edit.set_text(resp_text or "")

    def analyze(self):
        req = self.req_edit.text().strip()
        if not req:
            self.output.setPlainText("Add a request first.")
            return
        key = self.ctx.config.api_key()
        if not key:
            self.output.setMarkdown(
                "**No API key.** Set `ANTHROPIC_API_KEY` in your environment, or add "
                "a key under **Settings**.")
            return
        self.analyze_btn.setEnabled(False)
        self.output.setPlainText("Analyzing…")
        self.worker = AIWorker(
            req, self.resp_edit.text(), self.note.text(),
            key, self.ctx.config["ai_model"], int(self.ctx.config["ai_max_tokens"]))
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def on_done(self, text):
        self.analyze_btn.setEnabled(True)
        try:
            self.output.setMarkdown(text)
        except Exception:
            self.output.setPlainText(text)

    def on_failed(self, err):
        self.analyze_btn.setEnabled(True)
        self.output.setMarkdown(f"**Error:** {err}")

    # ---- AI payload generation -> Intruder ----
    def gen_payloads(self):
        req = self.req_edit.text().strip()
        if not req:
            self.output.setPlainText("Add a request first.")
            return
        key = self.ctx.config.api_key()
        if not key:
            self.output.setMarkdown("**No API key.** Set `ANTHROPIC_API_KEY` or add one in Settings.")
            return
        self.payloads_btn.setEnabled(False)
        self.output.setPlainText("Generating payloads…")
        self._pworker = AIPayloadWorker(
            req, self.resp_edit.text(), self.note.text(),
            key, self.ctx.config["ai_model"], 1200)
        self._pworker.done.connect(self.on_payloads)
        self._pworker.failed.connect(self.on_failed_payloads)
        self._pworker.start()

    def on_payloads(self, payloads):
        self.payloads_btn.setEnabled(True)
        if not payloads:
            self.output.setMarkdown("No payloads returned.")
            return
        self.main.load_intruder_payloads(self.req_edit.text(), payloads)
        self.output.setMarkdown(
            f"Loaded **{len(payloads)}** payloads into Intruder.\n\n```\n"
            + "\n".join(payloads) + "\n```")

    def on_failed_payloads(self, err):
        self.payloads_btn.setEnabled(True)
        self.output.setMarkdown(f"**Error:** {err}")
