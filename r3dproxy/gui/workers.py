"""Background workers so network / AI calls never block the GUI thread."""
from __future__ import annotations
import subprocess

from PySide6.QtCore import QThread, Signal

from ..core import sender as sender_mod
from ..core import raw_sender as raw_sender_mod
from ..core import ai_client


class ProcessWorker(QThread):
    """Run an external command, streaming combined stdout/stderr line by line."""
    line = Signal(str)
    done = Signal(int)     # return code (127 = not found)

    def __init__(self, argv, cwd=None):
        super().__init__()
        self.argv = argv
        self.cwd = cwd
        self.proc = None
        self._stop = False

    def run(self):
        try:
            self.proc = subprocess.Popen(
                self.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=self.cwd)
        except FileNotFoundError:
            self.line.emit(f"[error] command not found: {self.argv[0]}")
            self.done.emit(127)
            return
        except Exception as e:
            self.line.emit(f"[error] {e}")
            self.done.emit(1)
            return
        try:
            for line in self.proc.stdout:
                if self._stop:
                    break
                self.line.emit(line.rstrip("\n"))
        except Exception:
            pass
        rc = self.proc.wait()
        self.done.emit(rc)

    def stop(self):
        self._stop = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


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

    def __init__(self, request_text, response_text, note, cfg):
        super().__init__()
        self.args = (request_text, response_text, note)
        self.cfg = cfg

    def run(self):
        try:
            out = ai_client.analyze(*self.args, **self.cfg)
            self.done.emit(out)
        except Exception as e:
            self.failed.emit(str(e))


class AIPayloadWorker(QThread):
    done = Signal(list)
    failed = Signal(str)

    def __init__(self, request_text, response_text, note, cfg):
        super().__init__()
        self.args = (request_text, response_text, note)
        self.cfg = cfg

    def run(self):
        try:
            payloads = ai_client.suggest_payloads(*self.args, **self.cfg)
            self.done.emit(payloads)
        except Exception as e:
            self.failed.emit(str(e))
