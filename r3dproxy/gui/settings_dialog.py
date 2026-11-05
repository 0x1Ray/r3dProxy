"""Settings dialog: proxy, scope, sender, AI, match & replace, CA export."""
from __future__ import annotations
import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
                               QLineEdit, QSpinBox, QCheckBox, QComboBox,
                               QPushButton, QPlainTextEdit, QTabWidget, QWidget,
                               QLabel, QFileDialog, QMessageBox, QGroupBox)

from .. import config as config_mod


class SettingsDialog(QDialog):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Settings")
        self.resize(640, 560)
        v = QVBoxLayout(self)

        tabs = QTabWidget()
        v.addWidget(tabs)
        tabs.addTab(self._proxy_tab(), "Proxy")
        tabs.addTab(self._ai_tab(), "AI")
        tabs.addTab(self._sender_tab(), "Sender")
        tabs.addTab(self._mr_tab(), "Match & Replace")
        tabs.addTab(self._ca_tab(), "CA cert")

        bar = QHBoxLayout()
        bar.addStretch(1)
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
        save = QPushButton("Save"); save.setObjectName("accent"); save.clicked.connect(self.save)
        bar.addWidget(cancel); bar.addWidget(save)
        v.addLayout(bar)

    def _proxy_tab(self):
        w = QWidget(); f = QFormLayout(w)
        self.listen_host = QLineEdit(self.ctx.config["listen_host"])
        self.listen_port = QSpinBox(); self.listen_port.setRange(1, 65535)
        self.listen_port.setValue(int(self.ctx.config["listen_port"]))
        self.scope = QPlainTextEdit("\n".join(self.ctx.config["scope"] or []))
        self.scope.setPlaceholderText("one host substring per line; empty = all hosts in scope")
        f.addRow("Listen host", self.listen_host)
        f.addRow("Listen port", self.listen_port)
        f.addRow("Scope (intercept only)", self.scope)
        f.addRow(QLabel("Changing host/port takes effect after 'Restart proxy'."))
        return w

    def _ai_tab(self):
        w = QWidget(); f = QFormLayout(w)
        self.ai_model = QLineEdit(self.ctx.config["ai_model"])
        self.ai_tokens = QSpinBox(); self.ai_tokens.setRange(256, 8192)
        self.ai_tokens.setValue(int(self.ctx.config["ai_max_tokens"]))
        self.ai_key = QLineEdit(self.ctx.config["ai_api_key"])
        self.ai_key.setEchoMode(QLineEdit.Password)
        self.ai_key.setPlaceholderText("overridden by ANTHROPIC_API_KEY env var if set")
        f.addRow("Model", self.ai_model)
        f.addRow("Max tokens", self.ai_tokens)
        f.addRow("API key", self.ai_key)
        f.addRow(QLabel("Prefer the ANTHROPIC_API_KEY environment variable over storing a key here."))
        return w

    def _sender_tab(self):
        w = QWidget(); f = QFormLayout(w)
        self.s_timeout = QSpinBox(); self.s_timeout.setRange(1, 300)
        self.s_timeout.setValue(int(self.ctx.config["sender_timeout"]))
        self.s_verify = QCheckBox("Verify TLS certificates")
        self.s_verify.setChecked(bool(self.ctx.config["sender_verify_tls"]))
        self.s_redir = QCheckBox("Follow redirects")
        self.s_redir.setChecked(bool(self.ctx.config["sender_follow_redirects"]))
        f.addRow("Timeout (s)", self.s_timeout)
        f.addRow("", self.s_verify)
        f.addRow("", self.s_redir)
        return w

    def _mr_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.addWidget(QLabel(
            "One rule per line (JSON):\n"
            '{"enabled":true,"part":"request","where":"header|body|first_line",'
            '"match":"regex","replace":"text","name":"label"}'))
        import json
        self.mr_edit = QPlainTextEdit(
            "\n".join(json.dumps(r) for r in (self.ctx.config["match_replace"] or [])))
        v.addWidget(self.mr_edit)
        return w

    def _ca_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        ca_path = config_mod.CA_DIR / "mitmproxy-ca-cert.pem"
        v.addWidget(QLabel(
            "To intercept HTTPS, install r3dProxy's CA certificate in your browser/OS "
            "trust store. The certificate is generated on first run at:"))
        path_lbl = QLineEdit(str(ca_path)); path_lbl.setReadOnly(True)
        v.addWidget(path_lbl)
        exp = QPushButton("Export CA certificate…")
        exp.clicked.connect(lambda: self._export_ca(ca_path))
        v.addWidget(exp)
        v.addWidget(QLabel(
            "Firefox: Settings → Privacy → View Certificates → Authorities → Import.\n"
            "System (Debian/Ubuntu): copy to /usr/local/share/ca-certificates/ as .crt "
            "then run 'sudo update-ca-certificates'."))
        v.addStretch(1)
        return w

    def _export_ca(self, ca_path: Path):
        if not ca_path.exists():
            QMessageBox.warning(self, "CA not found",
                                "The CA is created on first proxy run. Start the proxy, "
                                "send one HTTPS request, then export.")
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Export CA", "r3dproxy-ca.pem",
                                              "PEM (*.pem *.crt)")
        if dest:
            try:
                shutil.copyfile(ca_path, dest)
                QMessageBox.information(self, "Exported", f"Saved to {dest}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def save(self):
        import json
        c = self.ctx.config
        c["listen_host"] = self.listen_host.text().strip() or "127.0.0.1"
        c["listen_port"] = self.listen_port.value()
        c["scope"] = [s.strip() for s in self.scope.toPlainText().splitlines() if s.strip()]
        c["ai_model"] = self.ai_model.text().strip()
        c["ai_max_tokens"] = self.ai_tokens.value()
        c["ai_api_key"] = self.ai_key.text().strip()
        c["sender_timeout"] = self.s_timeout.value()
        c["sender_verify_tls"] = self.s_verify.isChecked()
        c["sender_follow_redirects"] = self.s_redir.isChecked()
        rules = []
        for line in self.mr_edit.toPlainText().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rules.append(json.loads(line))
            except Exception:
                QMessageBox.warning(self, "Invalid rule", f"Skipping invalid JSON:\n{line}")
        c["match_replace"] = rules
        c.save()
        self.accept()
