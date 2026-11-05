"""Byte-exact raw-socket HTTP/1.1 sender.

Unlike the requests-based sender, this writes (almost) exactly the bytes you
typed — no header reordering, no automatic header injection. That fidelity is
what makes CRLF injection, CORS/Origin games, odd header casing and malformed
requests testable. Content-Length can optionally be recomputed (needed when a
scanner swaps payloads of different lengths into the body).
"""
from __future__ import annotations
import socket
import ssl
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import httptext
from .sender import SendResult, Target


@dataclass
class RawResp:
    ok: bool
    status: Optional[int]
    reason: str
    headers: List[Tuple[str, str]]
    body: str
    raw_head: str
    elapsed_ms: int
    error: str = ""

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def headers_lower(self):
        return {k.lower(): v for k, v in self.headers}


def _build_wire(request_text: str, fix_content_length: bool) -> bytes:
    start_line, headers, body = httptext.split_message(request_text)
    body_bytes = body.encode("utf-8", "replace")
    if fix_content_length:
        has_cl = any(k.lower() == "content-length" for k, _ in headers)
        is_chunked = any(k.lower() == "transfer-encoding" and "chunked" in v.lower()
                         for k, v in headers)
        if body_bytes and not is_chunked:
            headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
            headers.append(("Content-Length", str(len(body_bytes))))
        elif has_cl and not body_bytes:
            headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
    lines = [start_line] + [f"{k}: {v}" for k, v in headers]
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")
    return head + body_bytes


def _recv_all(sock, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    deadline = time.time() + timeout
    header_done = False
    header_blob = b""
    content_length = None
    chunked = False
    body_start = 0
    total = b""
    try:
        while True:
            if time.time() > deadline:
                break
            try:
                data = sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            total += data
            if not header_done:
                idx = total.find(b"\r\n\r\n")
                if idx != -1:
                    header_done = True
                    header_blob = total[:idx]
                    body_start = idx + 4
                    low = header_blob.lower()
                    for line in header_blob.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":", 1)[1].strip())
                            except Exception:
                                pass
                        if line.lower().startswith(b"transfer-encoding:") and b"chunked" in line.lower():
                            chunked = True
            if header_done and content_length is not None:
                if len(total) - body_start >= content_length:
                    break
            if header_done and chunked:
                if total.rstrip().endswith(b"0") or b"\r\n0\r\n\r\n" in total:
                    break
    except Exception:
        pass
    return total


def request_raw(request_text: str, target: Target, *, timeout=20, verify=False,
                fix_content_length=True) -> RawResp:
    wire = _build_wire(request_text, fix_content_length)
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((target.host, target.port), timeout=timeout)
        if target.tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target.host)
        sock.sendall(wire)
        raw = _recv_all(sock, timeout)
        elapsed = int((time.time() - t0) * 1000)
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return RawResp(False, None, "", [], "", elapsed, error=str(e))
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass

    return _parse(raw, elapsed)


def _parse(raw: bytes, elapsed: int) -> RawResp:
    idx = raw.find(b"\r\n\r\n")
    if idx == -1:
        head = raw
        body = b""
    else:
        head = raw[:idx]
        body = raw[idx + 4:]
    text_head = head.decode("latin-1", "replace")
    lines = text_head.split("\r\n")
    status = None
    reason = ""
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    body_text = body.decode("utf-8", "replace")
    return RawResp(True, status, reason, headers, body_text, text_head, elapsed)


def send(request_text: str, target: Target, *, timeout=20, verify=False,
         follow_redirects=False, fix_content_length=False) -> SendResult:
    """Repeater/Intruder-compatible wrapper returning a SendResult.

    follow_redirects is accepted for signature parity but ignored (raw mode
    intentionally does not follow redirects)."""
    r = request_raw(request_text, target, timeout=timeout, verify=verify,
                    fix_content_length=fix_content_length)
    if not r.ok:
        return SendResult(False, None, "", "", r.elapsed_ms, 0, error=r.error)
    full = r.raw_head + "\r\n\r\n" + r.body
    return SendResult(True, r.status, r.reason, full, r.elapsed_ms,
                      len(r.body.encode("utf-8", "replace")))
