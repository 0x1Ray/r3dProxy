"""Local OAST (out-of-band) callback listener for confirming blind vulns.

Runs a tiny HTTP server in a thread. Any inbound request is logged and pushed to
the GUI via a Qt signal. Generate a unique-token URL, drop it into a payload
(SSRF/XXE/RCE/blind-SQLi), and if the target's backend calls back, you get proof.

For callbacks from the public internet you must make this reachable — run it on
a VPS, port-forward, or set a public base URL (e.g. an interactsh domain) in
Settings. On localhost it still confirms SSRF-to-internal and same-host tests.
"""
from __future__ import annotations
import http.server
import socketserver
import threading
import time
import uuid

from PySide6.QtCore import QObject, Signal


class OASTBridge(QObject):
    hit = Signal(dict)          # {time, src, method, path, token, headers, ua}
    started = Signal(str, int)
    stopped = Signal()


class _Handler(http.server.BaseHTTPRequestHandler):
    bridge = None
    base_host = ""

    def _log_hit(self):
        path = self.path
        token = ""
        # token is the first path segment or a ?t= query param
        seg = path.strip("/").split("/", 1)[0]
        if seg:
            token = seg.split("?")[0]
        info = {
            "time": time.strftime("%H:%M:%S"),
            "src": self.client_address[0],
            "method": self.command,
            "path": path,
            "token": token,
            "ua": self.headers.get("User-Agent", ""),
            "headers": {k: v for k, v in self.headers.items()},
        }
        if _Handler.bridge:
            _Handler.bridge.hit.emit(info)
        body = b"r3dproxy-oast-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        self._log_hit()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(min(length, 65536))
        except Exception:
            pass
        self._log_hit()

    def log_message(self, *a):
        pass


class OASTListener:
    def __init__(self, bridge: OASTBridge):
        self.bridge = bridge
        self._httpd = None
        self._thread = None
        self.host = "0.0.0.0"
        self.port = 0
        self.running = False

    def start(self, host="0.0.0.0", port=9999):
        if self.running:
            return
        _Handler.bridge = self.bridge
        try:
            self._httpd = socketserver.ThreadingTCPServer((host, port), _Handler)
            self._httpd.daemon_threads = True
        except Exception as e:
            self.bridge.stopped.emit()
            raise e
        self.host, self.port = host, port
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.running = True
        self.bridge.started.emit(host, port)

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
        self.running = False
        self.bridge.stopped.emit()

    @staticmethod
    def new_token() -> str:
        return "r3d" + uuid.uuid4().hex[:12]
