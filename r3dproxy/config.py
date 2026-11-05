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
    # AI — provider-agnostic. Default is free & local (Ollama + Qwen).
    # provider ids: ollama | openrouter-qwen | groq | openai | anthropic
    "ai_provider": "ollama",
    "ai_base_url": "http://localhost:11434/v1",
    "ai_model": "qwen2.5",
    "ai_max_tokens": 1500,
    # Fallback key (prefer env vars: ANTHROPIC_API_KEY for Claude, else
    # R3DPROXY_AI_KEY / OPENAI_API_KEY).
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
    # Passive auditing of proxy traffic
    "passive_enabled": True,
    # Obsidian/notes export
    "obsidian_vault": "",
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
        """Resolve the AI key for the current provider (env first)."""
        provider = self.data.get("ai_provider", "ollama")
        if provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY", "") or self.data.get("ai_api_key", "")
        return (os.environ.get("R3DPROXY_AI_KEY", "")
                or os.environ.get("OPENAI_API_KEY", "")
                or self.data.get("ai_api_key", ""))

    def ai_config(self) -> dict:
        return {
            "provider": self.data.get("ai_provider", "ollama"),
            "base_url": self.data.get("ai_base_url", ""),
            "model": self.data.get("ai_model", ""),
            "api_key": self.api_key(),
            "max_tokens": int(self.data.get("ai_max_tokens", 1500)),
        }

    def ai_needs_key(self) -> bool:
        from .core.ai_client import PROVIDERS
        return PROVIDERS.get(self.data.get("ai_provider", "ollama"), {}).get("needs_key", True)


def ensure_dirs():
    for d in (CONFIG_DIR, CA_DIR, SESSIONS_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
