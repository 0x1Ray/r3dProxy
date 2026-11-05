"""Save/load a working session (HTTP history + repeater tabs) as JSON."""
from __future__ import annotations
import json
import time
from pathlib import Path
from typing import List

from ..config import SESSIONS_DIR
from .flowstore import FlowRecord, FlowStore


def serialize_store(store: FlowStore) -> list:
    out = []
    for rec in store.all():
        out.append({
            "fid": rec.fid, "method": rec.method, "host": rec.host, "url": rec.url,
            "scheme": rec.scheme, "status": rec.status, "length": rec.length,
            "mime": rec.mime, "ts": rec.ts,
            "request_text": rec.request_text, "response_text": rec.response_text,
        })
    return out


def save_session(path: str, store: FlowStore, repeater_tabs: List[dict]):
    data = {
        "version": 1,
        "saved_at": time.time(),
        "history": serialize_store(store),
        "repeater": repeater_tabs,
    }
    Path(path).write_text(json.dumps(data, indent=2), "utf-8")


def load_session(path: str) -> dict:
    data = json.loads(Path(path).read_text("utf-8"))
    return data


def populate_store(store: FlowStore, history: list):
    store.clear()
    for h in history:
        rec = FlowRecord(
            fid=h.get("fid", ""), method=h.get("method", ""), host=h.get("host", ""),
            url=h.get("url", ""), scheme=h.get("scheme", "http"),
            status=h.get("status"), length=h.get("length"), mime=h.get("mime", ""),
            ts=h.get("ts", time.time()),
            request_text=h.get("request_text", ""), response_text=h.get("response_text", ""),
        )
        store.add(rec)


def default_session_path() -> str:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return str(SESSIONS_DIR / time.strftime("session-%Y%m%d-%H%M%S.json"))
