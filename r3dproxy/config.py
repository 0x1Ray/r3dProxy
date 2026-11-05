"""Persistent settings for r3dProxy, stored as JSON under ~/.r3dproxy/."""
from __future__ import annotations
import json
import os
from pathlib import Path

CONFIG_DIR = Path(os.path.expanduser("~")) / ".r3dproxy"
CONFIG_FILE = CONFIG_DIR / "settings.json"
# mitmproxy keeps its generated CA here by default when confdir points at it.
CA_DIR = CONFIG_DIR / "ca"
SESSIONS_DIR = CONFIG_DIR / "sessions"

DEFAULTS = {
    "listen_host": "127.0.0.1",
    "listen_port": 8080,
    "intercept_enabled": False,
    # Only intercept requests whose host matches the scope (empty = all).
    "scope": [],
    # AI / Claude
    "ai_model": "claude-sonnet-4-5",
    "ai_max_tokens": 1500,
    # The key is read from the env var ANTHROPIC_API_KEY first; this is a fallback.
    "ai_api_key": "",
    # Sender (Repeater / Intruder)
    "sender_timeout": 20,
    "sender_verify_tls": False,
    "sender_follow_redirects": False,
    # Match & replace rules: list of dicts
    #   {enabled, part: request|response, where: header|body|first_line,
    #    match (regex), replace, name}
    "match_replace": [],
    # OAST
    "oast_base": "",
}


class Config:
    def __init__(self):
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            if CONFIG_FILE.exists():
                loaded = json.loads(CONFIG_FILE.read_text("utf-8"))
                if isinstance(loaded, dict):
                    self.data.update(loaded)
        except Exception:
            # Corrupt config should never crash the app; fall back to defaults.
            pass

    def save(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(json.dumps(self.data, indent=2), "utf-8")
        except Exception:
            pass

    def __getitem__(self, k):
        return self.data.get(k, DEFAULTS.get(k))

    def __setitem__(self, k, v):
        self.data[k] = v

    def get(self, k, default=None):
        return self.data.get(k, DEFAULTS.get(k, default))

    def api_key(self) -> str:
        return os.environ.get("ANTHROPIC_API_KEY", "") or self.data.get("ai_api_key", "")


def ensure_dirs():
    for d in (CONFIG_DIR, CA_DIR, SESSIONS_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
