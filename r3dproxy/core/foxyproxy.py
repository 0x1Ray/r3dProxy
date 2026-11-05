"""Generate a FoxyProxy-importable config pointing at r3dProxy."""
from __future__ import annotations
import json


def build_config(host: str, port: int, title: str = "r3dProxy") -> str:
    """FoxyProxy Standard-compatible export (import via FoxyProxy → Import/Export).

    A single HTTP proxy that routes all URLs through r3dProxy. If your FoxyProxy
    version rejects the import, the manual steps in the dialog always work.
    """
    if host in ("0.0.0.0", "", None):
        host = "127.0.0.1"
    cfg = {
        "mode": "patterns",
        "proxies": [
            {
                "id": "r3dproxy",
                "active": True,
                "title": title,
                "color": "#e11d2a",
                "type": "http",
                "address": host,
                "port": str(port),
                "proxyDNS": True,
                "username": "",
                "password": "",
                "whitePatterns": [
                    {
                        "title": "all URLs",
                        "active": True,
                        "pattern": "*",
                        "type": "wildcard",
                        "protocols": "all",
                    }
                ],
                "blackPatterns": [],
            }
        ],
    }
    return json.dumps(cfg, indent=2)
