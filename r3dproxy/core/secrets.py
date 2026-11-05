"""Secret / credential detection and hidden-text detection.

Scans response bodies (including JS) for leaked keys, tokens and credentials —
one of the highest-value, lowest-effort bug-bounty findings. Inspired by the
detection ideas in agentshield, applied to HTTP responses instead of configs.
Matches are redacted in output so the report never stores a full live secret.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List

HIGH, MEDIUM, LOW, INFO = "High", "Medium", "Low", "Info"


@dataclass
class SecretHit:
    name: str
    severity: str
    redacted: str
    snippet: str


# (name, severity, compiled regex). Ordered specific → generic.
_RULES = [
    ("AWS access key id", HIGH, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", HIGH, re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,3}['\"=: ]\s*([0-9a-zA-Z/+]{40})\b")),
    ("Google API key", HIGH, re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth token", HIGH, re.compile(r"\bya29\.[0-9A-Za-z\-_]+")),
    ("GitHub token", HIGH, re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("GitHub fine-grained PAT", HIGH, re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b")),
    ("Slack token", HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Slack webhook", MEDIUM, re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("Stripe secret key", HIGH, re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("Twilio API key", HIGH, re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SendGrid key", HIGH, re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b")),
    ("Mailgun key", MEDIUM, re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("Private key block", HIGH, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token (JWT)", LOW, re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("DB connection string", HIGH, re.compile(r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+")),
    ("Firebase URL", INFO, re.compile(r"https://[a-z0-9.-]+\.firebaseio\.com")),
    ("Generic secret assignment", MEDIUM, re.compile(
        r"(?i)(?:api[_-]?key|secret|token|access[_-]?key|auth|passwd|password)"
        r"['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_./+]{16,64})['\"]")),
]

# zero-width / bidi-override characters used to hide text
_HIDDEN = re.compile(r"[​-‏‪-‮⁠⁦-⁩﻿]")


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 10:
        return s[:3] + "…"
    return s[:6] + "…" + s[-4:]


def scan(text: str) -> List[SecretHit]:
    hits = []
    seen = set()
    if not text:
        return hits
    for name, sev, rx in _RULES:
        for m in rx.finditer(text):
            full = m.group(0)
            key = (name, full[:20])
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 24)
            snippet = text[start:m.start() + 24].replace("\n", " ")
            hits.append(SecretHit(name, sev, _redact(full), snippet))
            if len(hits) >= 50:
                return hits
    return hits


def hidden_text(text: str) -> bool:
    return bool(_HIDDEN.search(text or ""))
