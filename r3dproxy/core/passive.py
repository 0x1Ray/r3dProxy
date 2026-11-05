"""Passive auditing: derive issues from a request/response pair without sending
any new requests. Runs on proxy traffic as you browse (Burp-style live audit)."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse, parse_qs

from . import httptext

HIGH, MEDIUM, LOW, INFO = "High", "Medium", "Low", "Info"
SEV_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


@dataclass
class Issue:
    name: str
    severity: str
    confidence: str
    detail: str
    url: str

    def key(self):
        return (self.name, self.url)


_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map")
_ERROR_SIGS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"\bat [\w.$]+\([\w.]+\.java:\d+\)", "Java stack trace"),
    (r"Warning: \w+\(\).*on line \d+", "PHP warning"),
    (r"Fatal error: ", "PHP fatal error"),
    (r"System\.\w+Exception", ".NET exception"),
    (r"org\.springframework\.", "Spring stack trace"),
    (r"SQLSTATE\[", "SQL error"),
    (r"ORA-\d{5}", "Oracle error"),
    (r"You have an error in your SQL syntax", "MySQL error"),
]
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")


def _headers_map(headers):
    out = {}
    for k, v in headers:
        out.setdefault(k.lower(), []).append(v)
    return out


def audit(request_text: str, response_text: str, url: str) -> List[Issue]:
    issues: List[Issue] = []
    if not response_text:
        return issues
    scheme = urlparse(url).scheme or "http"
    path = urlparse(url).path.lower()
    is_static = path.endswith(_STATIC_EXT)

    _sl, req_headers, req_body = httptext.split_message(request_text)
    _rsl, resp_headers, resp_body = httptext.split_message(response_text)
    rh = _headers_map(resp_headers)
    ctype = (rh.get("content-type", [""])[0]).lower()
    is_html = "html" in ctype
    status_line = _rsl.split(" ")
    is_error_status = len(status_line) > 1 and status_line[1].isdigit() and int(status_line[1]) >= 500

    def add(name, sev, conf, detail):
        issues.append(Issue(name, sev, conf, detail, url))

    # ---- security headers (only for top-level HTML docs) ----
    if is_html:
        if "content-security-policy" not in rh:
            add("Missing Content-Security-Policy", LOW, "Firm",
                "No CSP header — reduces XSS/clickjacking defense in depth.")
        if "x-content-type-options" not in rh:
            add("Missing X-Content-Type-Options", INFO, "Firm",
                "No 'nosniff' — browser may MIME-sniff responses.")
        if "x-frame-options" not in rh and "frame-ancestors" not in rh.get("content-security-policy", [""])[0].lower():
            add("Missing clickjacking protection", LOW, "Firm",
                "No X-Frame-Options and no CSP frame-ancestors.")
        if scheme == "https" and "strict-transport-security" not in rh:
            add("Missing Strict-Transport-Security", LOW, "Firm",
                "HTTPS response without HSTS.")

    # ---- cookies ----
    for sc in rh.get("set-cookie", []):
        low = sc.lower()
        cname = sc.split("=", 1)[0].strip()
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if scheme == "https" and "secure" not in low:
            flags.append("Secure")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            add(f"Cookie without {', '.join(flags)}", LOW, "Firm",
                f"Set-Cookie '{cname}' is missing: {', '.join(flags)}.")

    # ---- info disclosure headers ----
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        for v in rh.get(h, []):
            if re.search(r"\d", v):
                add(f"Version disclosure ({h})", INFO, "Firm",
                    f"{h}: {v}")

    # ---- CORS ----
    acao = rh.get("access-control-allow-origin", [""])[0]
    acac = (rh.get("access-control-allow-credentials", [""])[0]).lower()
    if acao == "*" and acac == "true":
        add("CORS: wildcard origin with credentials", MEDIUM, "Firm",
            "Access-Control-Allow-Origin: * together with credentials=true.")

    # ---- body-based checks (skip static assets) ----
    if not is_static and resp_body:
        body = resp_body[:300000]
        for rx, label in _ERROR_SIGS:
            if re.search(rx, body):
                sev = MEDIUM if is_error_status else LOW
                add(f"Verbose error / stack trace ({label})", sev, "Firm",
                    "Response leaks an internal error/stack trace.")
                break
        m = _PRIVATE_IP.search(body)
        if m:
            add("Private IP address disclosure", INFO, "Tentative",
                f"Response body contains a private IP: {m.group(0)}")

        # reflected parameters (potential XSS source)
        reflected = _reflected_params(url, req_body, body)
        if reflected:
            add("Reflected input", LOW, "Tentative",
                "Parameter value(s) reflected unencoded in the response: "
                + ", ".join(sorted(reflected)[:6])
                + " — test for XSS in the Scanner.")

    return issues


def _reflected_params(url: str, req_body: str, body: str) -> set:
    params = {}
    try:
        params.update({k: v for k, v in parse_qs(urlparse(url).query).items()})
    except Exception:
        pass
    try:
        params.update({k: v for k, v in parse_qs(req_body).items()})
    except Exception:
        pass
    reflected = set()
    for name, values in params.items():
        for val in values:
            if val and len(val) >= 4 and val in body:
                reflected.add(name)
                break
    return reflected
