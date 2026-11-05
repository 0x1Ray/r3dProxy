"""mitmproxy wrapper running in its own asyncio thread, bridged to Qt via signals.

The proxy runs a DumpMaster in a background thread with its own event loop.
Hooks run on that loop thread, so they emit Qt signals (queued, thread-safe)
to the GUI. The GUI drives interception by calling resume/drop, which are
marshalled back onto the loop thread via call_soon_threadsafe.
"""
from __future__ import annotations
import asyncio
import threading
from typing import Callable, Optional

from PySide6.QtCore import QObject, Signal

from mitmproxy import options, http
from mitmproxy.tools import dump

from . import httptext


class ProxyBridge(QObject):
    """Qt signals emitted from the proxy thread."""
    request_captured = Signal(str)        # fid
    request_intercepted = Signal(str)     # fid (paused, awaiting user)
    response_captured = Signal(str)       # fid
    flow_error = Signal(str, str)         # fid, message
    started = Signal(str, int)            # host, port
    stopped = Signal()
    log = Signal(str)


class _Addon:
    def __init__(self, engine: "ProxyEngine"):
        self.engine = engine

    # --- mitmproxy hooks (run on the proxy loop thread) ---
    def request(self, flow: http.HTTPFlow):
        eng = self.engine
        rec = eng._ensure_record(flow)
        rec.request_text = httptext.request_to_text(flow.request)

        # Apply request-side match & replace before anything else.
        eng._apply_match_replace(flow, part="request")

        eng.bridge.request_captured.emit(flow.id)

        if eng.intercept_enabled and eng._in_scope(flow.request.pretty_host):
            rec.intercepted = True
            flow.intercept()
            eng._paused[flow.id] = flow
            eng.bridge.request_intercepted.emit(flow.id)

    def response(self, flow: http.HTTPFlow):
        eng = self.engine
        rec = eng._ensure_record(flow)
        eng._apply_match_replace(flow, part="response")
        try:
            rec.status = flow.response.status_code
            rec.length = len(flow.response.raw_content or b"")
            rec.mime = flow.response.headers.get("content-type", "")
            rec.response_text = httptext.response_to_text(flow.response)
        except Exception:
            pass
        eng.bridge.response_captured.emit(flow.id)

    def error(self, flow: http.HTTPFlow):
        try:
            msg = str(flow.error) if flow.error else "unknown error"
        except Exception:
            msg = "error"
        self.engine.bridge.flow_error.emit(getattr(flow, "id", ""), msg)


class ProxyEngine:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.bridge = ProxyBridge()
        self.intercept_enabled = bool(config["intercept_enabled"])
        self._paused = {}            # fid -> flow (awaiting user decision)
        self._master = None
        self._loop = None
        self._thread = None
        self._running = False

    # ---------- lifecycle ----------
    def start(self):
        if self._running:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="r3dproxy-engine")
        self._thread.start()

    def _run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            opts = options.Options(
                listen_host=self.config["listen_host"],
                listen_port=int(self.config["listen_port"]),
            )
            master = dump.DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            # Keep mitmproxy's CA/confdir under our app dir for a stable cert.
            try:
                from ..config import CA_DIR
                master.options.update(confdir=str(CA_DIR))
            except Exception:
                pass
            master.addons.add(_Addon(self))
            self._master = master
            self._running = True
            self.bridge.started.emit(self.config["listen_host"], int(self.config["listen_port"]))
            loop.run_until_complete(master.run())
        except Exception as e:
            self.bridge.log.emit(f"Proxy engine stopped: {e}")
        finally:
            self._running = False
            self.bridge.stopped.emit()

    def stop(self):
        if self._master and self._loop:
            self._loop.call_soon_threadsafe(self._master.shutdown)

    @property
    def running(self) -> bool:
        return self._running

    # ---------- interception control (called from GUI thread) ----------
    def set_intercept(self, enabled: bool):
        self.intercept_enabled = bool(enabled)
        self.config["intercept_enabled"] = self.intercept_enabled
        if not enabled:
            # Release everything currently held.
            for fid in list(self._paused.keys()):
                self.forward(fid)

    def forward(self, fid: str, edited_text: Optional[str] = None):
        flow = self._paused.pop(fid, None)
        if not flow or not self._loop:
            return

        def _do():
            try:
                if edited_text is not None:
                    httptext.apply_text_to_request(flow.request, edited_text)
                    rec = self.store.get(fid)
                    if rec:
                        rec.request_text = httptext.request_to_text(flow.request)
                flow.resume()
            except Exception as e:
                self.bridge.log.emit(f"forward error: {e}")

        rec = self.store.get(fid)
        if rec:
            rec.intercepted = False
        self._loop.call_soon_threadsafe(_do)

    def drop(self, fid: str):
        flow = self._paused.pop(fid, None)
        if not flow or not self._loop:
            return

        def _do():
            try:
                flow.kill()
            except Exception as e:
                self.bridge.log.emit(f"drop error: {e}")

        rec = self.store.get(fid)
        if rec:
            rec.intercepted = False
        self._loop.call_soon_threadsafe(_do)

    def pending(self):
        """fids currently paused, in capture order."""
        return [r.fid for r in self.store.all() if r.fid in self._paused]

    # ---------- helpers ----------
    def _ensure_record(self, flow: http.HTTPFlow):
        from .flowstore import FlowRecord
        rec = self.store.get(flow.id)
        if rec is None:
            rec = FlowRecord(
                fid=flow.id,
                method=flow.request.method,
                host=flow.request.pretty_host,
                url=flow.request.pretty_url,
                scheme=flow.request.scheme,
                flow=flow,
            )
            self.store.add(rec)
        else:
            rec.flow = flow
        return rec

    def _in_scope(self, host: str) -> bool:
        scope = self.config["scope"] or []
        if not scope:
            return True
        host = (host or "").lower()
        return any(s.lower() in host for s in scope if s.strip())

    def _apply_match_replace(self, flow: http.HTTPFlow, part: str):
        import re
        rules = self.config["match_replace"] or []
        for rule in rules:
            try:
                if not rule.get("enabled", True):
                    continue
                if rule.get("part", "request") != part:
                    continue
                pat = rule.get("match", "")
                rep = rule.get("replace", "")
                if not pat:
                    continue
                where = rule.get("where", "body")
                obj = flow.request if part == "request" else flow.response
                if obj is None:
                    continue
                if where == "header":
                    for k in list(obj.headers.keys()):
                        new = re.sub(pat, rep, obj.headers[k])
                        obj.headers[k] = new
                elif where == "first_line":
                    if part == "request":
                        obj.path = re.sub(pat, rep, obj.path)
                else:  # body
                    try:
                        txt = obj.get_text(strict=False) or ""
                    except Exception:
                        txt = ""
                    obj.text = re.sub(pat, rep, txt)
            except Exception:
                continue
