"""Qt-free shared registry of OAST callbacks.

The OAST HTTP listener records every inbound hit here; the scanner engine reads
it to confirm blind vulnerabilities by token. Kept separate from oast.py so the
core/plugins layer can use it without importing PySide6.
"""
from __future__ import annotations
import threading
import uuid

_LOCK = threading.Lock()
_HITS = []  # list of dicts: {time, src, method, path, token, headers, ua}


def record(info: dict):
    with _LOCK:
        _HITS.append(info)


def seen(token: str):
    """Return hits whose token or path/headers contain the token."""
    if not token:
        return []
    with _LOCK:
        items = list(_HITS)
    out = []
    for h in items:
        if token == h.get("token") or token in h.get("path", ""):
            out.append(h)
            continue
        if any(token in str(v) for v in h.get("headers", {}).values()):
            out.append(h)
    return out


def clear():
    with _LOCK:
        _HITS.clear()


def new_token() -> str:
    return "r3d" + uuid.uuid4().hex[:12]
