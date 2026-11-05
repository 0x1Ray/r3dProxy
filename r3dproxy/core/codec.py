"""Encoding/decoding helpers and a simple diff, for the Tools tab. Pure funcs."""
from __future__ import annotations
import base64
import binascii
import html
import json
import urllib.parse
from difflib import SequenceMatcher


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8", "replace")).decode("ascii")


def b64_decode(s: str) -> str:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad).decode("utf-8", "replace")
    except Exception as e:
        return f"[base64 decode error: {e}]"


def hex_encode(s: str) -> str:
    return s.encode("utf-8", "replace").hex()


def hex_decode(s: str) -> str:
    s = "".join(s.split())
    try:
        return bytes.fromhex(s).decode("utf-8", "replace")
    except Exception as e:
        return f"[hex decode error: {e}]"


def html_encode(s: str) -> str:
    return html.escape(s)


def html_decode(s: str) -> str:
    return html.unescape(s)


def jwt_decode(s: str) -> str:
    """Decode a JWT's header and payload (no signature verification)."""
    parts = s.strip().split(".")
    if len(parts) < 2:
        return "[not a JWT: expected at least header.payload]"
    out = []
    for name, seg in (("header", parts[0]), ("payload", parts[1])):
        pad = "=" * (-len(seg) % 4)
        try:
            raw = base64.urlsafe_b64decode(seg + pad)
            try:
                obj = json.loads(raw)
                out.append(f"// {name}\n" + json.dumps(obj, indent=2, ensure_ascii=False))
            except Exception:
                out.append(f"// {name}\n" + raw.decode("utf-8", "replace"))
        except Exception as e:
            out.append(f"// {name} decode error: {e}")
    if len(parts) >= 3:
        out.append(f"// signature (b64url, not verified)\n{parts[2]}")
    return "\n\n".join(out)


OPERATIONS = {
    "URL encode": url_encode,
    "URL decode": url_decode,
    "Base64 encode": b64_encode,
    "Base64 decode": b64_decode,
    "Hex encode": hex_encode,
    "Hex decode": hex_decode,
    "HTML encode": html_encode,
    "HTML decode": html_decode,
    "JWT decode": jwt_decode,
}


def diff_lines(a: str, b: str):
    """Return a list of (tag, text) where tag in {'equal','add','del','chg'}.
    Line-oriented, suitable for colored rendering."""
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    sm = SequenceMatcher(None, a_lines, b_lines)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for line in a_lines[i1:i2]:
                out.append(("equal", line))
        elif tag == "delete":
            for line in a_lines[i1:i2]:
                out.append(("del", line))
        elif tag == "insert":
            for line in b_lines[j1:j2]:
                out.append(("add", line))
        elif tag == "replace":
            for line in a_lines[i1:i2]:
                out.append(("del", line))
            for line in b_lines[j1:j2]:
                out.append(("add", line))
    return out
