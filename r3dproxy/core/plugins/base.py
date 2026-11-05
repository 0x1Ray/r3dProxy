"""Plugin framework for the OWASP-oriented scanner.

A plugin tests one vulnerability class on one request. It produces a set of
test *cases* (each a concrete request built from the base request) and a
*detect* step per case. The ScanEngine runs baseline + control probes first so
detection can reduce false positives by comparing against them.

Injection point: wrap the value to test in the request with the marker §…§.
Header-based plugins (e.g. CORS) ignore the marker and rewrite the request
directly.

Write your own plugin by subclassing Plugin and dropping a .py file into
~/.r3dproxy/plugins/ that defines a module-level `plugin = YourPlugin()` or a
`PLUGINS = [...]` list.
"""
from __future__ import annotations
import random
import re
import string
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..raw_sender import request_raw, RawResp
from ..sender import Target

MARKER = "§"

# Confidence levels (ordered).
FIRM = "Firm"
HIGH = "High"
TENTATIVE = "Tentative"
INFO = "Info"
CONF_ORDER = {INFO: 0, TENTATIVE: 1, HIGH: 2, FIRM: 3}


@dataclass
class Case:
    label: str
    request_text: str
    payload: str
    timing: bool = False          # vulnerable -> noticeable delay
    meta: dict = field(default_factory=dict)


@dataclass
class Finding:
    plugin_id: str
    name: str
    owasp: str
    confidence: str
    point: str
    payload: str
    evidence: str
    case_label: str
    status: Optional[int] = None
    elapsed_ms: int = 0
    request_text: str = ""
    response_text: str = ""


def rand_token(n=8) -> str:
    return "r3d" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def split_marker(text: str):
    """Return (prefix, seed, suffix). seed is the text between the first §…§.
    If no marker, seed is '' and suffix is '' (prefix = whole text)."""
    m = re.search(rf"{MARKER}([^{MARKER}]*){MARKER}", text)
    if not m:
        return text, "", ""
    return text[:m.start()], m.group(1), text[m.end():]


def sub_marker(text: str, value: str) -> str:
    prefix, _seed, suffix = split_marker(text)
    if not suffix and MARKER not in text:
        return text  # no marker present
    return prefix + value + suffix


TIMING_DELAY = 5            # seconds the timing payloads try to sleep
TIMING_THRESHOLD_MS = 4000  # min delta over baseline to call it


class ScanEngine:
    def __init__(self, base_text: str, target: Target, *, timeout=20, verify=False,
                 progress_cb: Optional[Callable] = None, stop_flag=None,
                 oast_base: Optional[str] = None):
        self.base_text = base_text
        self.target = target
        self.timeout = timeout
        self.verify = verify
        self.marker = MARKER
        self._progress_cb = progress_cb
        self._stop_flag = stop_flag
        self.oast_base = (oast_base or "").rstrip("/") or None
        self.baseline: Optional[RawResp] = None
        self.control: Optional[RawResp] = None
        self.control_token = ""

    # ---- OAST (out-of-band) helpers ----
    def oast_available(self) -> bool:
        return bool(self.oast_base)

    def oast_probe(self):
        """Return (token, callback_url) for embedding in a payload."""
        from ..oast_registry import new_token
        token = new_token()
        return token, f"{self.oast_base}/{token}"

    def oast_confirmed(self, token: str, wait: float = 6.0) -> bool:
        import time as _t
        from ..oast_registry import seen
        deadline = _t.time() + wait
        while _t.time() < deadline:
            if seen(token):
                return True
            if self.stopped():
                return False
            _t.sleep(0.4)
        return bool(seen(token))

    def prepare(self):
        _p, seed, _s = split_marker(self.base_text)
        baseline_req = sub_marker(self.base_text, seed) if MARKER in self.base_text else self.base_text
        self.baseline = self._raw(baseline_req, timing=False)
        self.control_token = rand_token()
        if MARKER in self.base_text:
            control_req = sub_marker(self.base_text, seed + self.control_token)
            self.control = self._raw(control_req, timing=False)
        else:
            self.control = self.baseline

    def stopped(self) -> bool:
        return bool(self._stop_flag and self._stop_flag())

    def send(self, request_text: str, timing=False) -> RawResp:
        return self._raw(request_text, timing)

    def _raw(self, request_text: str, timing: bool) -> RawResp:
        timeout = max(self.timeout, TIMING_DELAY + 7) if timing else self.timeout
        return request_raw(request_text, self.target, timeout=timeout,
                           verify=self.verify, fix_content_length=True)

    def progress(self, label: str, resp: RawResp):
        if self._progress_cb:
            self._progress_cb(label, resp)


class Plugin:
    id = "base"
    name = "Base"
    owasp = ""
    description = ""
    uses_marker = True

    def build_cases(self, base_text: str, marker: str) -> List[Case]:
        return []

    def detect(self, case: Case, resp: RawResp, engine: ScanEngine) -> Optional[Finding]:
        return None

    # Default run loop; plugins may override for multi-probe logic.
    def run(self, engine: ScanEngine) -> List[Finding]:
        findings = []
        if self.uses_marker and MARKER not in engine.base_text:
            return findings
        for case in self.build_cases(engine.base_text, engine.marker):
            if engine.stopped():
                break
            resp = engine.send(case.request_text, timing=case.timing)
            engine.progress(f"{self.id}: {case.label}", resp)
            f = self.detect(case, resp, engine)
            if f:
                f.request_text = case.request_text
                f.response_text = (resp.raw_head + "\r\n\r\n" + resp.body) if resp.ok else f"[error] {resp.error}"
                findings.append(f)
        return findings

    # Helper to make a Finding from a case/resp.
    def _finding(self, case: Case, resp: RawResp, confidence: str, evidence: str,
                 point: str) -> Finding:
        return Finding(
            plugin_id=self.id, name=self.name, owasp=self.owasp,
            confidence=confidence, point=point, payload=case.payload,
            evidence=evidence, case_label=case.label,
            status=resp.status, elapsed_ms=resp.elapsed_ms,
        )


def point_label(base_text: str) -> str:
    _p, seed, _s = split_marker(base_text)
    return f"§{seed}§" if MARKER in base_text else "(request)"
