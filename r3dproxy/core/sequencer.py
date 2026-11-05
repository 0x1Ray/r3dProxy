"""Token randomness analysis (a practical subset of Burp Sequencer).

Estimates entropy from a sample of tokens (session IDs, CSRF tokens, reset
tokens, …). Not a FIPS test battery — it gives per-character-position Shannon
entropy, duplicate/sequence detection and a plain verdict so you can tell a
guessable token from a strong one.
"""
from __future__ import annotations
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List


@dataclass
class SeqResult:
    count: int
    unique: int
    duplicates: int
    min_len: int
    max_len: int
    charset: str
    charset_size: int
    bits_per_position: List[float]
    total_bits: float
    verdict: str
    notes: List[str] = field(default_factory=list)


def _shannon(freqs, n):
    h = 0.0
    for c in freqs.values():
        p = c / n
        if p > 0:
            h -= p * math.log2(p)
    return h


def analyze(tokens: List[str]) -> SeqResult:
    tokens = [t for t in (tokens or []) if t != ""]
    n = len(tokens)
    if n == 0:
        return SeqResult(0, 0, 0, 0, 0, "", 0, [], 0.0, "no data")

    unique = len(set(tokens))
    duplicates = n - unique
    lens = [len(t) for t in tokens]
    min_len, max_len = min(lens), max(lens)

    charset = "".join(sorted(set("".join(tokens))))
    notes = []

    # per-position entropy over the common prefix length
    L = min_len
    bits_per_pos = []
    for i in range(L):
        col = Counter(t[i] for t in tokens)
        bits_per_pos.append(_shannon(col, n))
    total_bits = sum(bits_per_pos)
    if max_len != min_len:
        notes.append(f"variable length ({min_len}–{max_len}); entropy computed over first {L} chars")

    # duplicates are a strong weakness signal
    if duplicates > 0:
        notes.append(f"{duplicates} duplicate token(s) in {n} samples — predictable or low entropy")

    # sequential / incremental detection
    if _looks_sequential(tokens):
        notes.append("tokens look sequential/incremental — effectively guessable")
        total_bits = min(total_bits, 8.0)

    # encoding hints
    enc = _encoding_hint(tokens)
    if enc:
        notes.append(f"format looks like {enc}")

    verdict = _verdict(total_bits, duplicates)
    return SeqResult(n, unique, duplicates, min_len, max_len, charset, len(charset),
                     bits_per_pos, round(total_bits, 1), verdict, notes)


def _verdict(bits, duplicates):
    if duplicates > 0:
        return "Weak (duplicates present)"
    if bits >= 80:
        return "Strong (≥80 bits)"
    if bits >= 48:
        return "Moderate (48–80 bits)"
    if bits >= 20:
        return "Weak (20–48 bits)"
    return "Very weak (<20 bits)"


def _looks_sequential(tokens):
    # all numeric and monotonic?
    if all(re.fullmatch(r"\d+", t) for t in tokens) and len(tokens) >= 3:
        nums = [int(t) for t in tokens]
        diffs = {b - a for a, b in zip(nums, nums[1:])}
        if len(diffs) == 1:
            return True
    return False


def _encoding_hint(tokens):
    sample = tokens[0]
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", sample):
        return "UUID"
    if re.fullmatch(r"\d+", sample):
        return "numeric"
    if re.fullmatch(r"[0-9a-fA-F]+", sample) and len(sample) % 2 == 0:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", sample) and len(sample) >= 16:
        return "base64/base64url"
    return ""
