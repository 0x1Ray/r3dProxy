"""Reusable HTTP message editor / viewer with lightweight syntax highlighting."""
from __future__ import annotations
import re

from PySide6.QtCore import Qt, QRegularExpression
from PySide6.QtGui import (QSyntaxHighlighter, QTextCharFormat, QColor, QFont,
                           QTextDocument)
from PySide6.QtWidgets import QPlainTextEdit

from . import theme


class _HttpHighlighter(QSyntaxHighlighter):
    def __init__(self, doc: QTextDocument):
        super().__init__(doc)
        self.rules = []

        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            return f

        # First line: METHOD / status
        self.rules.append((QRegularExpression(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b"), fmt(theme.ACCENT, True)))
        self.rules.append((QRegularExpression(r"^HTTP/\d\.\d\s+\d{3}"), fmt(theme.ACCENT, True)))
        # Header names
        self.rules.append((QRegularExpression(r"^[A-Za-z0-9\-]+(?=:)"), fmt("#6cb6ff")))
        # Intruder markers §...§
        self.rules.append((QRegularExpression(r"§[^§]*§"), fmt(theme.WARN, True)))

    def highlightBlock(self, text: str):
        for rx, f in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), f)


class HttpEditor(QPlainTextEdit):
    def __init__(self, read_only=False, parent=None):
        super().__init__(parent)
        self.setReadOnly(read_only)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        f = QFont("DejaVu Sans Mono")
        f.setStyleHint(QFont.Monospace)
        f.setPointSize(10)
        self.setFont(f)
        self.setTabStopDistance(28)
        self._hl = _HttpHighlighter(self.document())

    def set_text(self, text: str):
        self.setPlainText(text or "")

    def text(self) -> str:
        return self.toPlainText()
