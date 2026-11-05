"""Convert mitmproxy Request/Response objects to/from editable raw HTTP text.

Editing model (same idea as Burp): the user edits the *message* — the start
line, headers and body. The connection target (scheme/host/port) is a property
of the flow, not of the text, so it is never parsed back out of the text. This
keeps edited requests from silently breaking their routing.
"""
from __future__ import annotations
from typing import Optional

CRLF = "\r\n"


def _decode(b: bytes) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else str(b)


def request_to_text(request) -> str:
    """mitmproxy HTTPRequest -> raw text (origin-form target)."""
    target = request.path or "/"
    # request.http_version is already like "HTTP/1.1".
    start = f"{request.method} {target} {request.http_version}"
    lines = [start]
    for k, v in request.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    head = CRLF.join(lines) + CRLF + CRLF
    body = ""
    try:
        if request.raw_content:
            body = _decode(request.raw_content)
    except Exception:
        body = ""
    return head + body


def response_to_text(response) -> str:
    if response is None:
        return ""
    start = f"{response.http_version} {response.status_code} {response.reason or ''}".rstrip()
    lines = [start]
    for k, v in response.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    head = CRLF.join(lines) + CRLF + CRLF
    body = ""
    try:
        # .text decompresses; fall back to raw.
        body = response.get_text(strict=False)
        if body is None:
            body = _decode(response.raw_content or b"")
    except Exception:
        body = _decode(response.raw_content or b"")
    return head + body


def split_message(text: str):
    """Return (start_line, [(name, value)], body_str). Tolerant of \\n or \\r\\n."""
    text = text.replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    head_lines = head.split("\n")
    start_line = head_lines[0] if head_lines else ""
    headers = []
    for line in head_lines[1:]:
        if not line.strip():
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
    return start_line, headers, body


def apply_text_to_request(request, text: str) -> None:
    """Parse edited text and write method/target/version/headers/body back onto
    an existing mitmproxy request. Scheme/host/port are preserved."""
    start_line, headers, body = split_message(text)
    parts = start_line.split(" ")
    if len(parts) >= 1 and parts[0]:
        request.method = parts[0]
    if len(parts) >= 2:
        request.path = parts[1]
    if len(parts) >= 3:
        request.http_version = parts[2]
    request.headers.clear()
    for name, value in headers:
        request.headers.add(name, value)
    request.content = body.encode("utf-8", "replace")


def build_from_text(text: str):
    """Parse a standalone raw request used by Repeater/Intruder.

    Returns dict: method, target, http_version, headers(list of tuples), body(str).
    """
    start_line, headers, body = split_message(text)
    parts = start_line.split(" ")
    method = parts[0] if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    return {
        "method": method,
        "target": target,
        "http_version": version,
        "headers": headers,
        "body": body,
    }
