"""r3dProxy main window: wires the proxy engine, tabs and cross-tab actions."""
from __future__ import annotations
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QToolBar,
                               QLabel, QCheckBox, QPushButton, QWidget, QHBoxLayout,
                               QSizePolicy, QMessageBox)

from .. import APP_NAME, __version__, config as config_mod
from ..core.flowstore import FlowStore
from ..core.proxy_engine import ProxyEngine
from ..core.sender import Target
from . import theme
from .proxy_tab import ProxyTab
from .target_tab import TargetTab
from .repeater_tab import RepeaterTab
from .intruder_tab import IntruderTab
from .scanner_tab import ScannerTab
from .sequencer_tab import SequencerTab
from .tools_tab import ToolsTab
from .oast_tab import OASTTab
from .issues_tab import IssuesTab
from .recon_tab import ReconTab
from .ai_tab import AITab
from .settings_dialog import SettingsDialog


class AppContext:
    def __init__(self):
        config_mod.ensure_dirs()
        self.config = config_mod.Config()
        self.store = FlowStore()
        from ..core.engagement import EngagementStore
        self.engagement = EngagementStore()
        self.api_issues = []
        self.api_seen = set()
        self.engine = ProxyEngine(self.config, self.store)


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(f"{APP_NAME} v{__version__}")
        try:
            from pathlib import Path
            from PySide6.QtGui import QIcon
            _ic = Path(__file__).parent / "assets" / "icon.png"
            if _ic.exists():
                self.setWindowIcon(QIcon(str(_ic)))
        except Exception:
            pass
        self.resize(1320, 860)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.proxy_tab = ProxyTab(ctx, self)
        self.target_tab = TargetTab(ctx, self)
        self.repeater_tab = RepeaterTab(ctx, self)
        self.intruder_tab = IntruderTab(ctx, self)
        self.scanner_tab = ScannerTab(ctx, self)
        self.sequencer_tab = SequencerTab(ctx, self)
        self.issues_tab = IssuesTab(ctx, self)
        self.tools_tab = ToolsTab(ctx, self)
        self.recon_tab = ReconTab(ctx, self)
        self.oast_tab = OASTTab(ctx, self)
        self.ai_tab = AITab(ctx, self)

        self.tabs.addTab(self.proxy_tab, "Proxy")
        self.tabs.addTab(self.target_tab, "Target")
        self.tabs.addTab(self.repeater_tab, "Repeater")
        self.tabs.addTab(self.intruder_tab, "Intruder")
        self.tabs.addTab(self.scanner_tab, "Scanner")
        self.tabs.addTab(self.sequencer_tab, "Sequencer")
        self.tabs.addTab(self.issues_tab, "Issues")
        self.tabs.addTab(self.recon_tab, "Recon")
        self.tabs.addTab(self.tools_tab, "Tools")
        self.tabs.addTab(self.oast_tab, "OAST")
        self.tabs.addTab(self.ai_tab, "AI Assistant")

        self._build_toolbar()
        self._wire_engine()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.statusBar().showMessage("Ready")

        if self.ctx.config["intercept_enabled"]:
            self.intercept_chk.setChecked(True)

        self.control_api = None
        self._start_control_api()
        self.start_proxy()

    def _start_control_api(self):
        if not self.ctx.config.get("api_enabled", True):
            return
        try:
            from ..core.control_api import ControlAPI
            from .. import config as cfgmod
            token = cfgmod.api_token()
            port = int(self.ctx.config.get("api_port", 8777))
            self.control_api = ControlAPI(self.ctx, token, port=port)
            self.control_api.start()
            self.statusBar().showMessage(f"Control API on 127.0.0.1:{port} (for the browser extension)", 6000)
        except Exception as e:
            self.statusBar().showMessage(f"Control API not started: {e}", 6000)

    # ---------------- toolbar ----------------
    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        self.proxy_status = QLabel("  ● proxy: starting…  ")
        tb.addWidget(self.proxy_status)

        self.start_btn = QPushButton("Restart proxy")
        self.start_btn.clicked.connect(self.restart_proxy)
        tb.addWidget(self.start_btn)

        tb.addSeparator()
        self.intercept_chk = QCheckBox("Intercept")
        self.intercept_chk.toggled.connect(self.on_intercept_toggled)
        tb.addWidget(self.intercept_chk)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)

        proxy_setup_btn = QPushButton("Proxy setup")
        proxy_setup_btn.clicked.connect(self.open_proxy_setup)
        tb.addWidget(proxy_setup_btn)

        export_btn = QPushButton("Export notes")
        export_btn.setToolTip("Export the engagement (recon → findings) as Obsidian Markdown notes")
        export_btn.clicked.connect(self.export_notes)
        tb.addWidget(export_btn)

        save_btn = QPushButton("Save session")
        save_btn.clicked.connect(self.save_session)
        load_btn = QPushButton("Load session")
        load_btn.clicked.connect(self.load_session)
        tb.addWidget(save_btn)
        tb.addWidget(load_btn)

        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self.open_settings)
        tb.addWidget(settings_btn)

    # ---------------- engine wiring ----------------
    def _wire_engine(self):
        b = self.ctx.engine.bridge
        b.started.connect(self.on_started)
        b.stopped.connect(self.on_stopped)
        b.request_captured.connect(self.proxy_tab.on_request_captured)
        b.response_captured.connect(self.proxy_tab.on_response_captured)
        b.response_captured.connect(self._on_response_for_issues)
        b.request_intercepted.connect(self.proxy_tab.on_request_intercepted)
        b.flow_error.connect(self.proxy_tab.on_flow_error)
        b.log.connect(lambda m: self.statusBar().showMessage(m, 8000))

    def start_proxy(self):
        self.ctx.engine.start()

    def restart_proxy(self):
        self.ctx.engine.stop()
        # New engine instance on the same context (old thread exits on shutdown).
        self.statusBar().showMessage("Restarting proxy…", 3000)
        old = self.ctx.engine
        self.ctx.engine = ProxyEngine(self.ctx.config, self.ctx.store)
        self._wire_engine()
        self.ctx.engine.set_intercept(self.intercept_chk.isChecked())
        self.ctx.engine.start()

    def on_started(self, host, port):
        self.proxy_status.setText(f"  ● proxy: {host}:{port}  ")
        self.proxy_status.setStyleSheet(f"color:{theme.OK};")
        self.statusBar().showMessage(f"Listening on {host}:{port}", 5000)

    def on_stopped(self):
        self.proxy_status.setText("  ● proxy: stopped  ")
        self.proxy_status.setStyleSheet(f"color:{theme.FG_DIM};")

    def _on_tab_changed(self, idx):
        if self.tabs.widget(idx) is self.target_tab:
            self.target_tab.rebuild()

    def _on_response_for_issues(self, fid):
        rec = self.ctx.store.get(fid)
        if rec:
            self.issues_tab.audit_record(rec)
            # also feed the control API's issue list (for the extension's /issues)
            if self.ctx.config.get("passive_enabled", True):
                try:
                    from ..core.control_api import accumulate_passive
                    accumulate_passive(self.ctx, rec.request_text, rec.response_text, rec.url)
                except Exception:
                    pass

    def on_intercept_toggled(self, on):
        self.ctx.engine.set_intercept(on)
        self.proxy_tab.refresh_intercept_queue()

    def open_settings(self):
        dlg = SettingsDialog(self.ctx, self)
        dlg.exec()

    def open_proxy_setup(self):
        from .proxy_setup_dialog import ProxySetupDialog
        ProxySetupDialog(self.ctx, self).exec()

    def export_notes(self):
        from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
        from ..core import engagement as eng
        scope = self.ctx.config.get("scope") or []
        default_name = scope[0] if scope else ""
        name, ok = QInputDialog.getText(self, "Export engagement",
                                        "Target name (note folder):", text=default_name)
        if not ok or not name.strip():
            return
        start_dir = self.ctx.config.get("obsidian_vault", "") or ""
        vault = QFileDialog.getExistingDirectory(self, "Choose Obsidian vault / notes folder", start_dir)
        if not vault:
            return
        self.ctx.config["obsidian_vault"] = vault
        self.ctx.config.save()
        try:
            path = eng.export_vault(
                vault, name.strip(), scope=scope, store=self.ctx.store,
                findings=self.scanner_tab._findings, issues=[i for i, _ in self.issues_tab._issues],
                engagement=self.ctx.engagement)
            QMessageBox.information(self, "Exported", f"Engagement notes written to:\n{path}")
            self.statusBar().showMessage(f"Exported notes → {path}", 6000)
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    # ---------------- session persistence ----------------
    def save_session(self):
        from ..core import session as session_mod
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Save session",
                                              session_mod.default_session_path(),
                                              "r3dProxy session (*.json)")
        if not path:
            return
        try:
            rep = self.repeater_tab.serialize_tabs()
            session_mod.save_session(path, self.ctx.store, rep)
            self.statusBar().showMessage(f"Session saved: {path}", 5000)
        except Exception as e:
            self.statusBar().showMessage(f"Save failed: {e}", 6000)

    def load_session(self):
        from ..core import session as session_mod
        from PySide6.QtWidgets import QFileDialog
        from ..config import SESSIONS_DIR
        path, _ = QFileDialog.getOpenFileName(self, "Load session", str(SESSIONS_DIR),
                                              "r3dProxy session (*.json)")
        if not path:
            return
        try:
            data = session_mod.load_session(path)
            session_mod.populate_store(self.ctx.store, data.get("history", []))
            self.proxy_tab.rebuild_from_store()
            self.repeater_tab.restore_tabs(data.get("repeater", []))
            self.statusBar().showMessage(f"Session loaded: {path}", 5000)
        except Exception as e:
            self.statusBar().showMessage(f"Load failed: {e}", 6000)

    # ---------------- cross-tab actions ----------------
    def send_to_repeater(self, rec):
        tgt = Target(host=rec.host, port=(443 if rec.scheme == "https" else 80),
                     tls=(rec.scheme == "https"))
        self.repeater_tab.new_tab(rec.request_text, tgt)
        self.tabs.setCurrentWidget(self.repeater_tab)

    def send_to_intruder(self, rec):
        tgt = Target(host=rec.host, port=(443 if rec.scheme == "https" else 80),
                     tls=(rec.scheme == "https"))
        self.intruder_tab.load(rec.request_text, tgt)
        self.tabs.setCurrentWidget(self.intruder_tab)

    def send_to_scanner(self, rec):
        tgt = Target(host=rec.host, port=(443 if rec.scheme == "https" else 80),
                     tls=(rec.scheme == "https"))
        self.scanner_tab.load(rec.request_text, tgt)
        self.tabs.setCurrentWidget(self.scanner_tab)

    def send_to_sequencer(self, rec):
        tgt = Target(host=rec.host, port=(443 if rec.scheme == "https" else 80),
                     tls=(rec.scheme == "https"))
        self.sequencer_tab.load(rec.request_text, tgt)
        self.tabs.setCurrentWidget(self.sequencer_tab)

    def send_to_csrf(self, rec):
        self.tools_tab.csrf.load(rec.request_text, rec.url)
        self.tabs.setCurrentWidget(self.tools_tab)

    def send_to_ai(self, req_text, resp_text):
        self.ai_tab.load(req_text, resp_text)
        self.tabs.setCurrentWidget(self.ai_tab)

    def load_intruder_payloads(self, request_text, payloads):
        self.intruder_tab.load_request_and_payloads(request_text, payloads)
        self.tabs.setCurrentWidget(self.intruder_tab)

    def closeEvent(self, ev):
        try:
            self.ctx.config.save()
            self.ctx.engine.stop()
            if self.control_api:
                self.control_api.stop()
        except Exception:
            pass
        super().closeEvent(ev)


def _install_excepthook():
    """Log uncaught exceptions to ~/.r3dproxy/crash.log and keep the app alive
    instead of letting a single slot error tear the window down."""
    import traceback
    import time as _t
    from .. import config as cfgmod

    def hook(exc_type, exc, tb):
        try:
            cfgmod.ensure_dirs()
            with open(cfgmod.CONFIG_DIR / "crash.log", "a", encoding="utf-8") as f:
                f.write(f"\n=== {_t.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                traceback.print_exception(exc_type, exc, tb, file=f)
        except Exception:
            pass
        traceback.print_exception(exc_type, exc, tb)   # still print to stderr

    sys.excepthook = hook


def main():
    _install_excepthook()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(theme.STYLESHEET)
    try:
        from pathlib import Path
        from PySide6.QtGui import QIcon
        icon = Path(__file__).parent / "assets" / "icon.png"
        if icon.exists():
            app.setWindowIcon(QIcon(str(icon)))
    except Exception:
        pass
    pal = app.palette()
    pal.setColor(QPalette.Window, QColor(theme.BG))
    pal.setColor(QPalette.Base, QColor(theme.BG2))
    pal.setColor(QPalette.Text, QColor(theme.FG))
    pal.setColor(QPalette.WindowText, QColor(theme.FG))
    app.setPalette(pal)

    ctx = AppContext()
    win = MainWindow(ctx)
    win.show()
    return app.exec()
