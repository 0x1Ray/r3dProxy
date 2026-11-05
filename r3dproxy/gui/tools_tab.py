"""Tools tab: Decoder/Encoder and a response Comparer."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCharFormat, QFont
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QLabel, QPlainTextEdit, QComboBox,
                               QTabWidget, QTextBrowser)

from . import theme
from .editor import HttpEditor
from ..core import codec


class DecoderWidget(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.op = QComboBox()
        self.op.addItems(list(codec.OPERATIONS.keys()))
        run = QPushButton("Apply"); run.setObjectName("accent"); run.clicked.connect(self.apply_op)
        to_input = QPushButton("Output → Input"); to_input.clicked.connect(self.cycle)
        clear = QPushButton("Clear"); clear.clicked.connect(self.clear)
        bar.addWidget(QLabel("Operation:")); bar.addWidget(self.op)
        bar.addWidget(run); bar.addWidget(to_input); bar.addStretch(1); bar.addWidget(clear)
        v.addLayout(bar)
        split = QSplitter(Qt.Vertical)
        self.inp = QPlainTextEdit(); self.inp.setPlaceholderText("input")
        self.out = QPlainTextEdit(); self.out.setReadOnly(True); self.out.setPlaceholderText("output")
        for w in (self.inp, self.out):
            w.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        split.addWidget(self.inp); split.addWidget(self.out)
        v.addWidget(split)

    def apply_op(self):
        fn = codec.OPERATIONS.get(self.op.currentText())
        if fn:
            self.out.setPlainText(fn(self.inp.toPlainText()))

    def cycle(self):
        self.inp.setPlainText(self.out.toPlainText())

    def clear(self):
        self.inp.clear(); self.out.clear()


class ComparerWidget(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        bar = QHBoxLayout()
        cmp = QPushButton("Compare"); cmp.setObjectName("accent"); cmp.clicked.connect(self.compare)
        bar.addStretch(1); bar.addWidget(cmp)
        top = QSplitter(Qt.Horizontal)
        self.a = HttpEditor(read_only=False); self.b = HttpEditor(read_only=False)
        top.addWidget(self.a); top.addWidget(self.b)
        v.addWidget(QLabel("Left (A) vs Right (B):"))
        v.addWidget(top, 2)
        v.addLayout(bar)
        self.result = QTextBrowser()
        self.result.setStyleSheet("font-family:'DejaVu Sans Mono',monospace;")
        v.addWidget(self.result, 2)

    def set_pair(self, a, b):
        self.a.set_text(a); self.b.set_text(b)

    def compare(self):
        rows = codec.diff_lines(self.a.text(), self.b.text())
        html = []
        colors = {"equal": theme.FG_DIM, "add": theme.OK, "del": theme.ACCENT}
        signs = {"equal": "  ", "add": "+ ", "del": "- "}
        for tag, line in rows:
            safe = (line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            html.append(f'<span style="color:{colors[tag]};white-space:pre">{signs[tag]}{safe}</span>')
        adds = sum(1 for t, _ in rows if t == "add")
        dels = sum(1 for t, _ in rows if t == "del")
        header = f'<div style="color:{theme.FG}">+{adds} / -{dels}</div>'
        self.result.setHtml(header + "<br>".join(html))


class CSRFWidget(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Paste a request; set the full URL; generate an HTML CSRF PoC."))
        from PySide6.QtWidgets import QLineEdit
        self.url = QLineEdit(); self.url.setPlaceholderText("https://target.com/path  (full URL the request hits)")
        v.addWidget(self.url)
        split = QSplitter(Qt.Horizontal)
        self.req = HttpEditor(read_only=False)
        self.out = HttpEditor(read_only=True)
        split.addWidget(self.req); split.addWidget(self.out)
        v.addWidget(split, 1)
        bar = QHBoxLayout()
        gen = QPushButton("Generate PoC"); gen.setObjectName("accent"); gen.clicked.connect(self.generate)
        save = QPushButton("Save…"); save.clicked.connect(self.save)
        bar.addStretch(1); bar.addWidget(save); bar.addWidget(gen)
        v.addLayout(bar)

    def load(self, request_text, url):
        self.req.set_text(request_text); self.url.setText(url)

    def generate(self):
        from ..core import csrf
        url = self.url.text().strip()
        if not url:
            # try to derive from Host header
            from ..core.httptext import split_message
            s, headers, _ = split_message(self.req.text())
            host = next((v for k, v in headers if k.lower() == "host"), "")
            target = s.split(" ")[1] if len(s.split(" ")) > 1 else "/"
            url = f"https://{host}{target}" if host else target
            self.url.setText(url)
        self.out.set_text(csrf.build_poc(self.req.text(), url))

    def save(self):
        from PySide6.QtWidgets import QFileDialog
        if not self.out.text().strip():
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save CSRF PoC", "csrf-poc.html", "HTML (*.html)")
        if dest:
            try:
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(self.out.text())
            except Exception:
                pass


class ToolsTab(QWidget):
    def __init__(self, ctx, main):
        super().__init__()
        self.ctx = ctx
        self.main = main
        v = QVBoxLayout(self)
        inner = QTabWidget()
        self.decoder = DecoderWidget()
        self.comparer = ComparerWidget()
        self.csrf = CSRFWidget()
        inner.addTab(self.decoder, "Decoder / Encoder")
        inner.addTab(self.comparer, "Comparer")
        inner.addTab(self.csrf, "CSRF PoC")
        v.addWidget(inner)
