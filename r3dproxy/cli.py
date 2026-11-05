"""r3dProxy headless CLI — run and drive r3dProxy without the GUI.

  python -m r3dproxy.cli serve [--port 8777] [--proxy-port 8080]
        start the intercepting proxy + local control API (for the browser
        extension / automation). Runs until Ctrl-C.
  python -m r3dproxy.cli scan URL --param NAME [--plugins xss,sqli] [--json]
  python -m r3dproxy.cli secrets (URL | --file PATH)
  python -m r3dproxy.cli passive URL
  python -m r3dproxy.cli tools [--install]
  python -m r3dproxy.cli token            print the control-API token
"""
from __future__ import annotations
import argparse
import json
import sys

from . import config as config_mod


def _ctx_lite():
    """Context for commands that don't need the proxy engine or Qt."""
    config_mod.ensure_dirs()

    class C:
        pass
    c = C()
    c.config = config_mod.Config()
    from .core.flowstore import FlowStore
    c.store = FlowStore()
    from .core.engagement import EngagementStore
    c.engagement = EngagementStore()
    c.api_issues = []
    c.api_seen = set()
    return c


def cmd_token(args):
    print(config_mod.api_token())


def cmd_tools(args):
    from .core import exttools
    if args.install:
        import subprocess, os
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "scripts", "install_tools.sh")
        sys.exit(subprocess.call(["bash", script] + (["--nosudo"] if args.nosudo else [])))
    for t, ok in exttools.status():
        print(f"[{'ok' if ok else '--'}] {t.name:16} ({t.category})  {'' if ok else t.install}")


def cmd_secrets(args):
    from .core import secrets as secrets_mod, sender as sender_mod
    from .core.control_api import _target
    from urllib.parse import urlparse
    if args.file:
        text = open(args.file, "r", encoding="utf-8", errors="replace").read()
    else:
        p = urlparse(args.url)
        res = sender_mod.send(f"GET {p.path or '/'} HTTP/1.1\r\nHost: {p.netloc}\r\n\r\n",
                              _target(args.url), timeout=15)
        text = res.response_text if res.ok else ""
    hits = secrets_mod.scan(text)
    for h in hits:
        print(f"[{h.severity}] {h.name}: {h.redacted}")
    if not hits:
        print("no secrets found")


def cmd_passive(args):
    from .core import passive as passive_mod, sender as sender_mod
    from .core.control_api import _target
    from urllib.parse import urlparse
    p = urlparse(args.url)
    res = sender_mod.send(f"GET {p.path or '/'} HTTP/1.1\r\nHost: {p.netloc}\r\n\r\n",
                          _target(args.url), timeout=15)
    resp = res.response_text if res.ok else ""
    issues = passive_mod.audit(f"GET {args.url} HTTP/1.1\r\nHost: {p.netloc}\r\n\r\n", resp, args.url)
    for i in sorted(issues, key=lambda x: passive_mod.SEV_ORDER.get(x.severity, 9)):
        print(f"[{i.severity}] {i.name} — {i.detail}")
    if not issues:
        print("no passive issues")


def cmd_scan(args):
    from .core.plugins import get_plugin
    from .core.plugins.base import ScanEngine, MARKER
    from .core.control_api import _build_marked_request
    req, target = _build_marked_request(args.url, args.param)
    if MARKER not in req:
        print(f"param '{args.param}' not found in URL"); sys.exit(2)
    cfg = config_mod.Config()
    oast = (cfg.get("oast_base") or "").strip() or None
    plugins = args.plugins.split(",") if args.plugins else ["xss", "lfi", "ssti", "openredirect", "crlf", "cors"]
    out = []
    for pid in plugins:
        try:
            eng = ScanEngine(req, target, timeout=12, oast_base=oast)
            eng.prepare()
            for f in get_plugin(pid).run(eng):
                out.append({"plugin": f.plugin_id, "name": f.name, "owasp": f.owasp,
                            "confidence": f.confidence, "point": f.point,
                            "payload": f.payload, "evidence": f.evidence})
        except Exception as e:
            print(f"[{pid} error] {e}", file=sys.stderr)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for f in out:
            print(f"[{f['confidence']}] {f['name']} ({f['owasp']}) — {f['evidence']}")
        if not out:
            print("no findings")


def cmd_serve(args):
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from .core.flowstore import FlowStore
    from .core.proxy_engine import ProxyEngine
    from .core.engagement import EngagementStore
    from .core.control_api import ControlAPI, accumulate_passive

    config_mod.ensure_dirs()

    class C:
        pass
    ctx = C()
    ctx.config = config_mod.Config()
    if args.proxy_port:
        ctx.config["listen_port"] = args.proxy_port
    ctx.store = FlowStore()
    ctx.engagement = EngagementStore()
    ctx.api_issues = []
    ctx.api_seen = set()
    ctx.engine = ProxyEngine(ctx.config, ctx.store)

    app = QApplication(sys.argv)
    ctx.engine.bridge.response_captured.connect(
        lambda fid: _audit_fid(ctx, fid))
    ctx.engine.start()

    token = config_mod.api_token()
    port = args.port or int(ctx.config.get("api_port", 8777))
    api = ControlAPI(ctx, token, port=port)
    api.start()

    print("r3dProxy headless")
    print(f"  proxy : {ctx.config['listen_host']}:{ctx.config['listen_port']}")
    print(f"  API   : http://127.0.0.1:{port}   token: {token}")
    print("  point your browser proxy + the r3dProxy extension here. Ctrl-C to stop.")
    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        api.stop()
        ctx.engine.stop()


def _audit_fid(ctx, fid):
    from .core.control_api import accumulate_passive
    if not ctx.config.get("passive_enabled", True):
        return
    rec = ctx.store.get(fid)
    if rec:
        scope = ctx.config.get("scope") or []
        if scope and not any(s.lower() in (rec.host or "").lower() for s in scope if s.strip()):
            return
        accumulate_passive(ctx, rec.request_text, rec.response_text, rec.url)


def main(argv=None):
    p = argparse.ArgumentParser(prog="r3dproxy", description="r3dProxy headless CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run proxy + control API headless")
    s.add_argument("--port", type=int, default=0, help="control API port")
    s.add_argument("--proxy-port", type=int, default=0, help="proxy listen port")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("scan", help="run scanner plugins on a URL param")
    s.add_argument("url")
    s.add_argument("--param", required=True)
    s.add_argument("--plugins", default="")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("secrets", help="scan a URL/file for leaked secrets")
    s.add_argument("url", nargs="?", default="")
    s.add_argument("--file", default="")
    s.set_defaults(func=cmd_secrets)

    s = sub.add_parser("passive", help="passive audit of a URL")
    s.add_argument("url")
    s.set_defaults(func=cmd_passive)

    s = sub.add_parser("tools", help="list / install external tools")
    s.add_argument("--install", action="store_true")
    s.add_argument("--nosudo", action="store_true")
    s.set_defaults(func=cmd_tools)

    s = sub.add_parser("token", help="print the control-API token")
    s.set_defaults(func=cmd_token)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
