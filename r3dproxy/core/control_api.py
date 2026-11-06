"""Local control API for r3dProxy.

A tiny token-authenticated HTTP API on 127.0.0.1 that lets external clients —
above all the browser extension — drive r3dProxy live while the pentester
browses their scope: run passive/secret/active scans on a URL or page, toggle
intercept, manage scope, run a recon tool, and read history. It runs inside the
GUI and in headless `serve` mode, so the extension works with or without the
window open.

Endpoints (JSON; all except /health require header X-r3d-Token):
  GET  /health
  GET  /scope                         -> {scope:[...]}
  POST /scope      {action,host}      -> add/remove a scope host
  GET  /intercept                     -> {enabled}
  POST /intercept  {enabled}          -> toggle interception
  POST /secrets    {text|url}         -> secret/credential hits
  POST /passive    {url|request,response} -> passive issues
  POST /scan       {url,param,plugins?}   -> active scanner findings
  POST /run        {tool,target|domain,wordlist?}  -> external tool output
  GET  /history?limit=50              -> recent flows
"""
from __future__ import annotations
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qsl, parse_qs

from .. import __version__
from . import secrets as secrets_mod
from . import passive as passive_mod
from . import sender as sender_mod
from . import exttools
from .sender import Target

QUICK_PLUGINS = ["xss", "lfi", "ssti", "openredirect", "crlf", "cors"]


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, ctx, token):
        super().__init__(addr, handler)
        self.ctx = ctx
        self.token = token


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- helpers ----
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-r3d-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            return {}

    def _authed(self):
        return self.headers.get("X-r3d-Token", "") == self.server.token

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        try:
            self._do_GET()
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def _do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            eng = self.server.ctx.engine
            return self._json({"ok": True, "app": "r3dProxy", "version": __version__,
                               "proxy_running": getattr(eng, "running", False)})
        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        if path == "/scope":
            return self._json({"scope": self.server.ctx.config.get("scope") or []})
        if path == "/intercept":
            return self._json({"enabled": bool(self.server.ctx.engine.intercept_enabled)})
        if path == "/issues":
            return self._json({"issues": list(getattr(self.server.ctx, "api_issues", []))})
        if path == "/tools":
            tools = [{"id": t.id, "name": t.name, "category": t.category,
                      "installed": t.installed(), "install": t.install}
                     for t in exttools.TOOLS]
            return self._json({"tools": tools})
        if path == "/history":
            q = parse_qs(urlparse(self.path).query)
            limit = int((q.get("limit", ["50"])[0]))
            snapshot = list(self.server.ctx.store.all())[-limit:]
            rows = [{"method": r.method, "host": r.host, "url": r.url,
                     "status": r.status, "length": r.length} for r in snapshot]
            return self._json({"history": rows})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        path = urlparse(self.path).path
        body = self._body()
        try:
            if path == "/scope":
                return self._scope(body)
            if path == "/intercept":
                en = bool(body.get("enabled"))
                self.server.ctx.engine.set_intercept(en)
                return self._json({"enabled": en})
            if path == "/secrets":
                return self._secrets(body)
            if path == "/passive":
                return self._passive(body)
            if path == "/scan":
                return self._scan(body)
            if path == "/run":
                return self._run(body)
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        return self._json({"error": "not found"}, 404)

    # ---- endpoint impls ----
    def _scope(self, body):
        cfg = self.server.ctx.config
        scope = list(cfg.get("scope") or [])
        host = (body.get("host") or "").strip()
        action = body.get("action", "add")
        if host:
            if action == "remove":
                scope = [s for s in scope if s != host]
            elif host not in scope:
                scope.append(host)
        cfg["scope"] = scope
        cfg.save()
        return self._json({"scope": scope})

    def _secrets(self, body):
        text = body.get("text")
        if text is None and body.get("url"):
            res = sender_mod.send(f"GET {urlparse(body['url']).path or '/'} HTTP/1.1\r\n"
                                  f"Host: {urlparse(body['url']).netloc}\r\n\r\n",
                                  _target(body["url"]), timeout=15)
            text = res.response_text if res.ok else ""
        hits = secrets_mod.scan(text or "")
        return self._json({"hits": [{"name": h.name, "severity": h.severity,
                                     "match": h.redacted, "context": h.snippet} for h in hits]})

    def _passive(self, body):
        url = body.get("url", "")
        request = body.get("request", "")
        response = body.get("response", "")
        if not response and url:
            res = sender_mod.send(f"GET {urlparse(url).path or '/'} HTTP/1.1\r\n"
                                  f"Host: {urlparse(url).netloc}\r\n\r\n",
                                  _target(url), timeout=15)
            if res.ok:
                response = res.response_text
            request = f"GET {url} HTTP/1.1\r\nHost: {urlparse(url).netloc}\r\n\r\n"
        if not response and body.get("text"):
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body["text"]
        issues = passive_mod.audit(request, response, url or "http://page/")
        return self._json({"issues": [{"name": i.name, "severity": i.severity,
                                       "confidence": i.confidence, "detail": i.detail,
                                       "url": i.url} for i in issues]})

    def _scan(self, body):
        from .plugins import get_plugin
        from .plugins.base import ScanEngine, MARKER
        url = body.get("url", "")
        param = body.get("param", "")
        if not url or not param:
            return self._json({"error": "need url and param"}, 400)
        req_text, target = _build_marked_request(url, param)
        if MARKER not in req_text:
            return self._json({"error": f"param '{param}' not found in url"}, 400)
        plugin_ids = body.get("plugins") or QUICK_PLUGINS
        oast_base = (self.server.ctx.config.get("oast_base") or "").strip() or None
        findings = []
        for pid in plugin_ids:
            try:
                eng = ScanEngine(req_text, target, timeout=12, oast_base=oast_base)
                eng.prepare()
                for f in get_plugin(pid).run(eng):
                    findings.append({"plugin": f.plugin_id, "name": f.name, "owasp": f.owasp,
                                     "confidence": f.confidence, "point": f.point,
                                     "payload": f.payload, "evidence": f.evidence})
            except Exception:
                continue
        return self._json({"findings": findings, "target": target.base()})

    def _run(self, body):
        import subprocess
        tool_id = body.get("tool", "")
        try:
            tool = exttools.get(tool_id)
        except KeyError:
            return self._json({"error": f"unknown tool {tool_id}"}, 400)
        if not tool.installed():
            return self._json({"error": f"{tool.name} not installed", "install": tool.install}, 400)
        wordlist = body.get("wordlist", "")
        if tool.category == exttools.FUZZER and not wordlist:
            from . import wordlists as wl
            wordlist = wl.materialize("builtin:paths-common")
        ctx = exttools.RunCtx(target=body.get("target", ""), domain=body.get("domain", ""),
                              wordlist=wordlist, extra=body.get("extra", ""))
        argv = exttools.build(tool_id, ctx)
        try:
            out = subprocess.run(argv, capture_output=True, text=True,
                                 timeout=int(body.get("timeout", 120)))
            return self._json({"cmd": argv, "rc": out.returncode,
                               "output": (out.stdout + out.stderr)[:100000]})
        except subprocess.TimeoutExpired:
            return self._json({"error": "tool timed out", "cmd": argv}, 504)


def _target(url: str) -> Target:
    p = urlparse(url)
    tls = p.scheme == "https"
    return Target(p.hostname or "", p.port or (443 if tls else 80), tls)


def _build_marked_request(url: str, param: str):
    p = urlparse(url)
    tls = p.scheme == "https"
    pairs = parse_qsl(p.query, keep_blank_values=True)
    parts = []
    for k, v in pairs:
        if k == param:
            parts.append(f"{k}=§{v}§")
        else:
            parts.append(f"{k}={v}")
    query = "&".join(parts)
    path = (p.path or "/") + ("?" + query if query else "")
    host = p.netloc
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: r3dProxy\r\nConnection: close\r\n\r\n"
    return req, Target(p.hostname or "", p.port or (443 if tls else 80), tls)


def accumulate_passive(ctx, request_text, response_text, url):
    """Run passive audit + secrets on a flow and append new issues to ctx.api_issues
    (de-duplicated). Used by headless serve and the GUI so GET /issues has data."""
    if not response_text:
        return
    if not hasattr(ctx, "api_issues"):
        ctx.api_issues = []
        ctx.api_seen = set()
    try:
        issues = passive_mod.audit(request_text, response_text, url or "http://page/")
    except Exception:
        return
    for i in issues:
        key = (i.name, i.url)
        if key in ctx.api_seen:
            continue
        ctx.api_seen.add(key)
        ctx.api_issues.append({"name": i.name, "severity": i.severity,
                               "confidence": i.confidence, "detail": i.detail, "url": i.url})


class ControlAPI:
    def __init__(self, ctx, token, host="127.0.0.1", port=8777):
        self.ctx = ctx
        self.token = token
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self):
        self._server = _Server((self.host, self.port), _Handler, self.ctx, self.token)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
