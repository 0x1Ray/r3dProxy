"""Proxy setup dialog: show the proxy address, copy it, export FoxyProxy config
and the CA certificate."""
from __future__ import annotations
import shutil
from pathlib import Path

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QGroupBox, QFileDialog,
                               QMessageBox, QApplication)

from . import theme
from .. import config as config_mod
from ..core import foxyproxy


class ProxySetupDialog(QDialog):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Proxy setup")
        self.resize(560, 520)
        v = QVBoxLayout(self)

        host = ctx.config["listen_host"]
        disp_host = "127.0.0.1" if host in ("0.0.0.0", "", None) else host
        port = int(ctx.config["listen_port"])
        self._host, self._port = disp_host, port

        # --- address block ---
        addr = QGroupBox("Point your browser's proxy here")
        av = QVBoxLayout(addr)
        row = QHBoxLayout()
        self.addr_edit = QLineEdit(f"{disp_host}:{port}")
        self.addr_edit.setReadOnly(True)
        f = self.addr_edit.font(); f.setPointSize(13); self.addr_edit.setFont(f)
        copy_all = QPushButton("Copy"); copy_all.clicked.connect(
            lambda: self._copy(f"{disp_host}:{port}"))
        row.addWidget(self.addr_edit, 1); row.addWidget(copy_all)
        av.addLayout(row)
        row2 = QHBoxLayout()
        ch = QPushButton(f"Copy host ({disp_host})"); ch.clicked.connect(lambda: self._copy(disp_host))
        cp = QPushButton(f"Copy port ({port})"); cp.clicked.connect(lambda: self._copy(str(port)))
        row2.addWidget(ch); row2.addWidget(cp); row2.addStretch(1)
        av.addLayout(row2)
        v.addWidget(addr)

        # --- FoxyProxy ---
        fox = QGroupBox("FoxyProxy / Proxy SwitchyOmega")
        fv = QVBoxLayout(fox)
        steps = QLabel(
            "1. Install FoxyProxy (Firefox or Chrome).\n"
            "2. Add a proxy → Type: HTTP, Host: the host above, Port: the port above.\n"
            "3. Turn it on and browse your target; HTTP history fills up.\n"
            "4. For HTTPS, install the CA certificate (below) once.\n\n"
            "Or import the ready-made config:")
        steps.setWordWrap(True)
        fv.addWidget(steps)
        exp = QPushButton("Export FoxyProxy config…")
        exp.setObjectName("accent")
        exp.clicked.connect(self.export_foxyproxy)
        fv.addWidget(exp)
        note = QLabel("If your FoxyProxy version rejects the import, the manual steps above "
                      "always work — it's just HTTP host + port.")
        note.setWordWrap(True); note.setStyleSheet(f"color:{theme.FG_DIM};")
        fv.addWidget(note)
        v.addWidget(fox)

        # --- CA cert ---
        ca = QGroupBox("HTTPS — CA certificate")
        cv = QVBoxLayout(ca)
        self.ca_path = config_mod.CA_DIR / "mitmproxy-ca-cert.pem"
        p = QLineEdit(str(self.ca_path)); p.setReadOnly(True)
        cv.addWidget(QLabel("Generated on first run; install it in your browser to intercept HTTPS:"))
        cv.addWidget(p)
        exca = QPushButton("Export CA certificate…"); exca.clicked.connect(self.export_ca)
        cv.addWidget(exca)
        v.addWidget(ca)

        # --- browser extension / control API ---
        ext = QGroupBox("Browser extension (live companion)")
        ev = QVBoxLayout(ext)
        from .. import config as cfgmod
        port = int(ctx.config.get("api_port", 8777))
        token = cfgmod.api_token()
        ev.addWidget(QLabel("Load the extension from the repo's extension/ folder "
                            "(Chrome: chrome://extensions → Load unpacked; Firefox: "
                            "about:debugging → Load Temporary Add-on), then in its settings set:"))
        base_row = QHBoxLayout()
        base_field = QLineEdit(f"http://127.0.0.1:{port}"); base_field.setReadOnly(True)
        cb1 = QPushButton("Copy"); cb1.clicked.connect(lambda: self._copy(base_field.text()))
        base_row.addWidget(QLabel("API:")); base_row.addWidget(base_field, 1); base_row.addWidget(cb1)
        ev.addLayout(base_row)
        tok_row = QHBoxLayout()
        tok_field = QLineEdit(token); tok_field.setReadOnly(True)
        cb2 = QPushButton("Copy token"); cb2.clicked.connect(lambda: self._copy(token))
        tok_row.addWidget(QLabel("Token:")); tok_row.addWidget(tok_field, 1); tok_row.addWidget(cb2)
        ev.addLayout(tok_row)
        v.addWidget(ext)

        bar = QHBoxLayout(); bar.addStretch(1)
        close = QPushButton("Close"); close.clicked.connect(self.accept)
        bar.addWidget(close); v.addLayout(bar)
        self._flash = QLabel(""); self._flash.setStyleSheet(f"color:{theme.OK};")
        v.addWidget(self._flash)

    def _copy(self, text):
        QApplication.clipboard().setText(text)
        self._flash.setText(f"copied: {text}")

    def export_foxyproxy(self):
        data = foxyproxy.build_config(self._host, self._port)
        dest, _ = QFileDialog.getSaveFileName(self, "Export FoxyProxy config",
                                              "r3dproxy-foxyproxy.json", "JSON (*.json)")
        if dest:
            try:
                Path(dest).write_text(data, "utf-8")
                self._flash.setText(f"saved: {dest}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def export_ca(self):
        if not self.ca_path.exists():
            QMessageBox.warning(self, "CA not found",
                                "The CA is created on first proxy run. Start the proxy, send one "
                                "HTTPS request, then export.")
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Export CA", "r3dproxy-ca.pem",
                                              "PEM (*.pem *.crt)")
        if dest:
            try:
                shutil.copyfile(self.ca_path, dest)
                self._flash.setText(f"saved: {dest}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
