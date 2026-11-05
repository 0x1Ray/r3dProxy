"""Thread-safe-ish store of captured flows. Mutated only from the GUI thread."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FlowRecord:
    fid: str
    method: str
    host: str
    url: str
    scheme: str = "http"
    status: Optional[int] = None
    length: Optional[int] = None
    mime: str = ""
    ts: float = field(default_factory=time.time)
    intercepted: bool = False
    # Raw text snapshots for display (filled on request/response hooks).
    request_text: str = ""
    response_text: str = ""
    # The live mitmproxy flow, kept so we can resume/kill/edit while paused.
    flow: object = None

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


class FlowStore:
    def __init__(self):
        self._by_id = {}
        self._order = []

    def add(self, rec: FlowRecord):
        if rec.fid not in self._by_id:
            self._order.append(rec.fid)
        self._by_id[rec.fid] = rec

    def get(self, fid) -> Optional[FlowRecord]:
        return self._by_id.get(fid)

    def all(self):
        return [self._by_id[f] for f in self._order if f in self._by_id]

    def clear(self):
        self._by_id.clear()
        self._order.clear()

    def __len__(self):
        return len(self._order)
