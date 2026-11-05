"""Sequencer tab: estimate token randomness from pasted tokens or by capturing
a token from repeated requests."""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QLineEdit, QComboBox, QSpinBox,
                               QPlainTextEdit, QGroupBox, QTextBrowser, QCheckBox)

from . import theme
from .editor import HttpEditor
from ..core import sequencer as seq
from ..core import sender as sender_mod
from ..core import raw_sender as raw_sender_mod
from ..core import intruder as intr
from ..core.sender import Target


class CaptureWorker(QThread):
    progress = Signal(int, int)        # done, total
    token = Signal(str)
    finished_all = Signal(list)

    def __init__(self, request_text, target, grep, count, opts):
        super().__init__()
        self.request_text = request_text
        self.target = target
        self.grep = grep
        self.count = count
        self.opts = opts
        self._stop = False
        self._tokens = []

    def stop(self):
        self._stop = True

    def run(self):
        mod = raw_sender_mod if self.opts.get("raw") else sender_mod
        for i in range(self.count):
            if self._stop:
                break
            res = mod.send(self.request_text, self.target,
                           timeout=self.opts.get("timeout", 20),
                           verify=self.opts.get("verify", False))
            tok = intr.grep_extract(res.response_text, self.grep) if res.ok else ""
            if tok:
                self._tokens.append(tok)
                self.token.emit(tok)
            self.progress.emit(i + 1, self.count)
        self.finished_all.emit(self._tokens)


class SequencerTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        self.worker = None

        split = QSplitter(Qt.Horizontal)
        root = QVBoxLayout(self); root.addWidget(split)

        # ---- left: inputs ----
        left = QWidget(); lv = QVBoxLayout(left)

        cap = QGroupBox("Live capture (send a request repeatedly, extract the token)")
        cv = QVBoxLayout(cap)
        tbar = QHBoxLayout()
        tbar.addWidget(QLabel("Target:"))
        self.scheme = QComboBox(); self.scheme.addItems(["http", "https"])
        self.host = QLineEdit(); self.host.setPlaceholderText("host")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(443)
        tbar.addWidget(self.scheme); tbar.addWidget(self.host, 2)
        tbar.addWidget(QLabel(":")); tbar.addWidget(self.port)
        cv.addLayout(tbar)
        self.req_edit = HttpEditor(read_only=False)
        self.req_edit.setPlaceholderText("request that returns a fresh token each time")
        cv.addWidget(self.req_edit, 2)
        gbar = QHBoxLayout()
        gbar.addWidget(QLabel("Grep-extract (regex):"))
        self.grep = QLineEdit(); self.grep.setPlaceholderText(r"e.g. Set-Cookie: session=([^;]+)   or   \"csrf\":\"(\w+)\"")
        gbar.addWidget(self.grep, 1)
        cv.addLayout(gbar)
        rbar = QHBoxLayout()
        rbar.addWidget(QLabel("count:"))
        self.count = QSpinBox(); self.count.setRange(2, 5000); self.count.setValue(100)
        rbar.addWidget(self.count)
        self.raw_chk = QCheckBox("raw socket"); rbar.addWidget(self.raw_chk)
        rbar.addStretch(1)
        self.cap_btn = QPushButton("Capture & analyze"); self.cap_btn.setObjectName("accent")
        self.cap_btn.clicked.connect(self.capture)
        self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop)
        rbar.addWidget(self.stop_btn); rbar.addWidget(self.cap_btn)
        cv.addLayout(rbar)
        lv.addWidget(cap, 3)

        paste = QGroupBox("Or paste tokens (one per line)")
        pv = QVBoxLayout(paste)
        self.tokens_edit = QPlainTextEdit()
        pv.addWidget(self.tokens_edit)
        an = QPushButton("Analyze pasted"); an.clicked.connect(self.analyze_pasted)
        pv.addWidget(an)
        lv.addWidget(paste, 2)
        split.addWidget(left)

        # ---- right: report ----
        right = QGroupBox("Analysis")
        rv = QVBoxLayout(right)
        self.progress = QLabel("idle"); rv.addWidget(self.progress)
        self.report = QTextBrowser()
        self.report.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        rv.addWidget(self.report)
        split.addWidget(right)
        split.setSizes([620, 620])

    def load(self, request_text, target):
        self.req_edit.set_text(request_text)
        self.scheme.setCurrentText(target.scheme)
        self.host.setText(target.host); self.port.setValue(target.port)

    def current_target(self):
        return Target(self.host.text().strip(), self.port.value(),
                      self.scheme.currentText() == "https")

    def capture(self):
        tgt = self.current_target()
        if not tgt.host:
            self.progress.setText("set a host"); return
        if not self.grep.text().strip():
            self.progress.setText("set a grep-extract pattern to pull the token"); return
        opts = {"timeout": self.ctx.config["sender_timeout"],
                "verify": self.ctx.config["sender_verify_tls"],
                "raw": self.raw_chk.isChecked()}
        self.tokens_edit.clear()
        self.cap_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.worker = CaptureWorker(self.req_edit.text(), tgt, self.grep.text().strip(),
                                    self.count.value(), opts)
        self.worker.progress.connect(lambda d, t: self.progress.setText(f"capturing {d}/{t}"))
        self.worker.token.connect(lambda tk: self.tokens_edit.appendPlainText(tk))
        self.worker.finished_all.connect(self.on_captured)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()

    def on_captured(self, tokens):
        self.cap_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.progress.setText(f"captured {len(tokens)} tokens")
        self._render(seq.analyze(tokens))

    def analyze_pasted(self):
        tokens = [t for t in self.tokens_edit.toPlainText().splitlines() if t.strip()]
        self._render(seq.analyze(tokens))

    def _render(self, r):
        if r.count == 0:
            self.report.setPlainText("No tokens to analyze.")
            return
        color = theme.OK if "Strong" in r.verdict else (
            theme.WARN if "Moderate" in r.verdict else theme.ACCENT)
        lines = [f'<div style="font-size:15px;color:{color}"><b>{r.verdict}</b></div>',
                 f"<pre>",
                 f"samples        : {r.count} ({r.unique} unique, {r.duplicates} duplicate)",
                 f"length         : {r.min_len}" + (f"–{r.max_len}" if r.max_len != r.min_len else ""),
                 f"charset        : {r.charset_size} chars  [{_short(r.charset)}]",
                 f"estimated bits : {r.total_bits}",
                 "</pre>"]
        if r.bits_per_position:
            lines.append("<b>per-position entropy (bits):</b><pre>")
            for i, b in enumerate(r.bits_per_position):
                bar = "█" * int(round(b)) if b > 0 else "·"
                lines.append(f"  pos {i:>2}: {b:4.1f} {bar}")
            lines.append("</pre>")
        if r.notes:
            lines.append("<b>notes:</b><pre>")
            for n in r.notes:
                lines.append(f"  • {n}")
            lines.append("</pre>")
        self.report.setHtml("\n".join(lines))


def _short(s, n=40):
    return s if len(s) <= n else s[:n] + "…"
