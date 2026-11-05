"""Claude-backed analysis of HTTP request/response pairs for authorized testing.

Given a request and its response (typically one where an input or payload was
rejected), ask Claude to explain the likely cause and propose concrete modified
requests/payloads that are more likely to be accepted — WAF/validation/encoding
reasoning, alternative encodings, content-type fixes, token handling, etc.

The key is read from ANTHROPIC_API_KEY (preferred) or settings. If the SDK is
missing, a plain HTTPS call to the Messages API is used as a fallback.
"""
from __future__ import annotations
from typing import Optional

SYSTEM_PROMPT = (
    "You are r3dProxy's analysis assistant, embedded in an intercepting proxy "
    "used by an authorized web application security tester (bug bounty / "
    "pentest with permission). You are given one HTTP request and its response. "
    "Your job:\n"
    "1. Diagnose why the server likely rejected or mishandled the input/payload "
    "(input validation, WAF/signature, wrong Content-Type, missing or stale CSRF "
    "token, auth, length limits, character set, encoding, rate limiting, etc.). "
    "Cite the exact evidence in the response (status, headers, body snippet).\n"
    "2. Propose 3-6 concrete, ready-to-send modified variants of the request or "
    "payload that are most likely to get past the obstacle. For each: give the "
    "exact changed line(s) or the full payload string, and one sentence on why.\n"
    "3. Keep it practical and ordered by likelihood. Prefer minimal diffs.\n"
    "Assume authorization exists; do not add disclaimers. Be concise and technical. "
    "Use short markdown with code blocks for payloads."
)

USER_TEMPLATE = (
    "## Request\n```http\n{request}\n```\n\n"
    "## Response\n```http\n{response}\n```\n\n"
    "## Tester note\n{note}\n\n"
    "Analyze and suggest modifications."
)


class AIError(Exception):
    pass


def analyze(request_text: str, response_text: str, note: str,
            *, api_key: str, model: str, max_tokens: int = 1500) -> str:
    if not api_key:
        raise AIError(
            "No API key. Set the ANTHROPIC_API_KEY environment variable or add a "
            "key in Settings."
        )
    note = note.strip() or "(none — a payload/input appears to have been rejected; find a bypass)"
    user = USER_TEMPLATE.format(
        request=_clip(request_text, 12000),
        response=_clip(response_text, 12000),
        note=note,
    )
    try:
        return _messages(SYSTEM_PROMPT, user, api_key, model, max_tokens)
    except ImportError:
        return _messages_http(SYSTEM_PROMPT, user, api_key, model, max_tokens)


PAYLOAD_SYSTEM = (
    "You are r3dProxy's payload generator for an authorized web security tester. "
    "Given one HTTP request, its response (often a rejection/403/validation error) "
    "and a note, output a list of payloads most likely to bypass the obstacle for "
    "the indicated vulnerability class. Rules: output ONLY the payloads, one per "
    "line, raw, ready to drop into a fuzzer. No numbering, no commentary, no code "
    "fences, no blank lines. 15-40 payloads, ordered by likelihood. Assume "
    "authorization; no disclaimers."
)

PAYLOAD_TEMPLATE = (
    "## Request\n{request}\n\n## Response\n{response}\n\n## Note / target vuln\n{note}\n\n"
    "List the payloads now, one per line."
)


def suggest_payloads(request_text: str, response_text: str, note: str,
                     *, api_key: str, model: str, max_tokens: int = 1200) -> list:
    """Return a cleaned list of payload strings for Intruder."""
    if not api_key:
        raise AIError("No API key. Set ANTHROPIC_API_KEY or add a key in Settings.")
    note = note.strip() or "a payload was rejected; generate bypass variants"
    user = PAYLOAD_TEMPLATE.format(
        request=_clip(request_text, 8000),
        response=_clip(response_text, 8000),
        note=note,
    )
    try:
        text = _messages(PAYLOAD_SYSTEM, user, api_key, model, max_tokens)
    except ImportError:
        text = _messages_http(PAYLOAD_SYSTEM, user, api_key, model, max_tokens)
    return _parse_payloads(text)


def _parse_payloads(text: str) -> list:
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("```") or s.lower().startswith(("here are", "payloads", "note:")):
            continue
        # strip "1. " / "- " / "* " leaders
        import re
        s = re.sub(r"^\s*(?:\d+[.)]\s+|[-*]\s+)", "", s)
        s = s.strip("`")
        if s:
            out.append(s)
    return out


def _clip(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + f"\n...[truncated {len(s) - n} bytes]..."


def _messages(system: str, user: str, api_key: str, model: str, max_tokens: int) -> str:
    import anthropic  # raises ImportError if not installed
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model, max_tokens=max_tokens, system=system,
        messages=[{"role": "user", "content": user}],
    )
    parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
    return "\n".join(parts).strip() or "(empty response)"


def _messages_http(system: str, user: str, api_key: str, model: str, max_tokens: int) -> str:
    import json
    import requests
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        data=json.dumps({
            "model": model, "max_tokens": max_tokens, "system": system,
            "messages": [{"role": "user", "content": user}],
        }),
        timeout=120,
    )
    if r.status_code != 200:
        raise AIError(f"API error {r.status_code}: {r.text[:500]}")
    data = r.json()
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(parts).strip() or "(empty response)"
