"""Standalone HTTP sender for Repeater and Intruder.

Sends a raw, user-controlled request directly to a target (independent of the
proxy loop). Uses requests for robust TLS/redirect/encoding handling.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Optional

import requests
import urllib3

from . import httptext

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Target:
    host: str
    port: int
    tls: bool

    @property
    def scheme(self):
        return "https" if self.tls else "http"

    def base(self):
        default = (self.tls and self.port == 443) or (not self.tls and self.port == 80)
        hostport = self.host if default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{hostport}"


@dataclass
class SendResult:
    ok: bool
    status: Optional[int]
    reason: str
    response_text: str
    elapsed_ms: int
    length: int
    error: str = ""


def _normalise_target(raw_target: str, base: str) -> str:
    if raw_target.startswith("http://") or raw_target.startswith("https://"):
        return raw_target
    if not raw_target.startswith("/"):
        raw_target = "/" + raw_target
    return base + raw_target


def send(raw_request: str, target: Target, *, timeout=20, verify=False,
         follow_redirects=False) -> SendResult:
    parsed = httptext.build_from_text(raw_request)
    url = _normalise_target(parsed["target"], target.base())

    headers = {}
    for name, value in parsed["headers"]:
        # requests sets Host/Content-Length itself; keep user's Host if given.
        if name.lower() == "content-length":
            continue
        headers[name] = value

    body = parsed["body"].encode("utf-8", "replace") if parsed["body"] else None

    t0 = time.time()
    try:
        resp = requests.request(
            parsed["method"], url,
            headers=headers, data=body,
            timeout=timeout, verify=verify,
            allow_redirects=follow_redirects, stream=False,
        )
        elapsed = int((time.time() - t0) * 1000)
        text = _response_to_text(resp)
        return SendResult(
            ok=True, status=resp.status_code, reason=resp.reason or "",
            response_text=text, elapsed_ms=elapsed,
            length=len(resp.content or b""),
        )
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return SendResult(ok=False, status=None, reason="", response_text="",
                          elapsed_ms=elapsed, length=0, error=str(e))


def _response_to_text(resp) -> str:
    ver = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp.raw, "version", 11), "HTTP/1.1")
    lines = [f"{ver} {resp.status_code} {resp.reason or ''}".rstrip()]
    for k, v in resp.headers.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        body = resp.text
    except Exception:
        body = ""
    return head + body
