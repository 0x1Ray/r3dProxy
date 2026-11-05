"""Intruder attack engine: the four Burp-style attack types + grep-extract.

Positions are marked in the template with §…§. Attack types:
- sniper:        one payload set; one position at a time (others at their seed).
- battering_ram: one payload set; the same payload in every position at once.
- pitchfork:     one payload set per position; iterate in lockstep.
- cluster_bomb:  one payload set per position; every combination.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from itertools import product
from typing import List, Tuple, Iterator

MARKER = "§"
_POS_RE = re.compile(rf"{MARKER}([^{MARKER}]*){MARKER}")

SNIPER = "sniper"
BATTERING_RAM = "battering_ram"
PITCHFORK = "pitchfork"
CLUSTER_BOMB = "cluster_bomb"
ATTACK_TYPES = [SNIPER, BATTERING_RAM, PITCHFORK, CLUSTER_BOMB]


def find_positions(template: str) -> List[str]:
    """Return the seed text of each §…§ position, in order."""
    return _POS_RE.findall(template)


def count_positions(template: str) -> int:
    return len(find_positions(template))


def build_request(template: str, values: List[str]) -> str:
    """Replace the i-th §…§ with values[i]. Extra positions keep their seed."""
    idx = [0]
    seeds = find_positions(template)

    def repl(m):
        i = idx[0]
        idx[0] += 1
        if i < len(values) and values[i] is not None:
            return values[i]
        return m.group(1)  # seed
    return _POS_RE.sub(repl, template)


@dataclass
class Job:
    labels: Tuple[str, ...]        # payload(s) used, for the results table
    request_text: str
    position: int = -1             # sniper: which position (else -1)


def count_jobs(template: str, attack_type: str, sets: List[List[str]]) -> int:
    n = count_positions(template)
    if n == 0:
        return 0
    s0 = sets[0] if sets else []
    if attack_type == SNIPER:
        return n * len(s0)
    if attack_type == BATTERING_RAM:
        return len(s0)
    usable = [s for s in sets[:n] if s]
    if len(usable) < n:
        return 0
    if attack_type == PITCHFORK:
        return min(len(s) for s in usable)
    if attack_type == CLUSTER_BOMB:
        total = 1
        for s in usable:
            total *= len(s)
        return total
    return 0


def generate(template: str, attack_type: str, sets: List[List[str]]) -> Iterator[Job]:
    """Yield Jobs for the chosen attack type.

    sets: list of payload lists. Sniper/battering_ram use sets[0]. Pitchfork and
    cluster_bomb use one set per position (sets[i] for position i).
    """
    seeds = find_positions(template)
    n = len(seeds)
    if n == 0:
        return

    if attack_type == SNIPER:
        payloads = sets[0] if sets else []
        for pos in range(n):
            for p in payloads:
                values = list(seeds)
                values[pos] = p
                yield Job(labels=(p,), request_text=build_request(template, values), position=pos)
        return

    if attack_type == BATTERING_RAM:
        payloads = sets[0] if sets else []
        for p in payloads:
            values = [p] * n
            yield Job(labels=(p,), request_text=build_request(template, values))
        return

    # pitchfork / cluster_bomb need one set per position
    usable = [sets[i] if i < len(sets) and sets[i] else [] for i in range(n)]
    if any(len(s) == 0 for s in usable):
        return

    if attack_type == PITCHFORK:
        for combo in zip(*usable):
            yield Job(labels=tuple(combo), request_text=build_request(template, list(combo)))
        return

    if attack_type == CLUSTER_BOMB:
        for combo in product(*usable):
            yield Job(labels=tuple(combo), request_text=build_request(template, list(combo)))
        return


def grep_extract(response_text: str, pattern: str) -> str:
    """Return the first regex group (or whole match) found in the response."""
    if not pattern:
        return ""
    try:
        m = re.search(pattern, response_text, re.I | re.S)
    except re.error:
        return "[bad regex]"
    if not m:
        return ""
    return (m.group(1) if m.groups() else m.group(0))[:120]


def grep_match(response_text: str, needle: str) -> bool:
    if not needle:
        return False
    return needle in response_text
