"""Background workers so network / AI calls never block the GUI thread."""
from __future__ import annotations
from PySide6.QtCore import QThread, Signal

from ..core import sender as sender_mod
from ..core import raw_sender as raw_sender_mod
from ..core import ai_client


class SendWorker(QThread):
    done = Signal(object)   # SendResult

    def __init__(self, raw_request, target, opts):
        super().__init__()
        self.raw_request = raw_request
        self.target = target
        self.opts = opts

    def run(self):
        mod = raw_sender_mod if self.opts.get("raw") else sender_mod
        res = mod.send(
            self.raw_request, self.target,
            timeout=self.opts.get("timeout", 20),
            verify=self.opts.get("verify", False),
            follow_redirects=self.opts.get("follow_redirects", False),
        )
        self.done.emit(res)


class AIWorker(QThread):
    done = Signal(str)
    failed = Signal(str)

    def __init__(self, request_text, response_text, note, api_key, model, max_tokens):
        super().__init__()
        self.args = (request_text, response_text, note)
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens

    def run(self):
        try:
            out = ai_client.analyze(
                *self.args, api_key=self.api_key, model=self.model,
                max_tokens=self.max_tokens,
            )
            self.done.emit(out)
        except Exception as e:
            self.failed.emit(str(e))


class AIPayloadWorker(QThread):
    done = Signal(list)
    failed = Signal(str)

    def __init__(self, request_text, response_text, note, api_key, model, max_tokens):
        super().__init__()
        self.args = (request_text, response_text, note)
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens

    def run(self):
        try:
            payloads = ai_client.suggest_payloads(
                *self.args, api_key=self.api_key, model=self.model,
                max_tokens=self.max_tokens,
            )
            self.done.emit(payloads)
        except Exception as e:
            self.failed.emit(str(e))
