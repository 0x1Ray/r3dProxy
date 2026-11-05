"""Engagement collector + Obsidian/Markdown export.

Gathers everything gathered against a scoped target — footprinting, recon tool
runs, subdomains, the site map, and findings (scanner + passive) — and writes it
as linked Markdown notes into an Obsidian vault (just a folder of .md files).
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
from urllib.parse import urlparse


@dataclass
class ReconRun:
    tool: str
    category: str
    target: str
    output: str
    ts: float = field(default_factory=time.time)


class EngagementStore:
    """Lives on the app context; tabs push recon artifacts into it."""
    def __init__(self):
        self.recon_runs: List[ReconRun] = []
        self.subdomains = set()
        self.discovered = []     # (url, status, length)
        self.notes = []          # free-form user notes

    def add_run(self, tool, category, target, output):
        self.recon_runs.append(ReconRun(tool, category, target, output))

    def add_subdomains(self, subs):
        self.subdomains.update(subs)

    def add_discovered(self, items):
        self.discovered.extend(items)


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (s or "target").strip())
    return s.strip("-") or "target"


def _in_scope(host, scope):
    host = (host or "").lower()
    if not scope:
        return True
    return any(s.lower() in host for s in scope if s.strip())


def export_vault(vault_dir: str, target_name: str, *, scope, store, findings,
                 issues, engagement: EngagementStore) -> str:
    """Write the engagement as linked notes. Returns the engagement folder path."""
    base = Path(vault_dir) / "r3dProxy" / _slug(target_name)
    base.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d %H:%M")

    # filter history to scope
    recs = [r for r in store.all() if _in_scope(r.host, scope)]
    hosts = sorted({r.host for r in recs})
    n_find = len(findings)
    n_iss = len(issues)

    # ---- main note ----
    main_md = [
        "---",
        f"target: {target_name}",
        f"date: {date}",
        "tags: [r3dproxy, recon, bugbounty]",
        "---",
        f"# {target_name} — engagement",
        "",
        f"- Scope: {', '.join(scope) if scope else '(none set)'}",
        f"- Hosts seen: {len(hosts)}",
        f"- Subdomains: {len(engagement.subdomains)}",
        f"- Recon runs: {len(engagement.recon_runs)}",
        f"- Findings: {n_find} · Passive issues: {n_iss}",
        "",
        "## Index",
        "- [[Recon]] — footprinting, subdomains, tool output",
        "- [[Site map]] — hosts and paths",
        "- [[Findings]] — scanner findings and passive issues",
        "- [[Assets]] — per-asset notes (domains, subdomains, IPs)",
        "",
    ]

    # ---- asset correlation (the smart layer) ----
    from . import assets as assets_mod
    asset_map = assets_mod.correlate(
        scope, store, engagement.recon_runs, engagement.subdomains,
        engagement.discovered, findings, issues, resolve=True)
    _write_assets(base, asset_map)
    main_md += ["## Assets", ""]
    by_type = {}
    for a in asset_map.values():
        by_type.setdefault(a.atype, []).append(a.name)
    for atype in ("domain", "subdomain", "ip"):
        names = sorted(by_type.get(atype, []))
        if names:
            main_md.append(f"### {atype}s ({len(names)})")
            main_md += [f"- [[{_slug(n)}]]" for n in names]
            main_md.append("")
    (base / f"{_slug(target_name)}.md").write_text("\n".join(main_md), "utf-8")

    # ---- Recon note ----
    recon_md = ["# Recon", "", f"_generated {date}_", ""]
    if engagement.subdomains:
        recon_md += ["## Subdomains", ""]
        recon_md += [f"- {s}" for s in sorted(engagement.subdomains)]
        recon_md += [""]
    if engagement.discovered:
        recon_md += ["## Discovered content", "", "| URL | Status | Length |", "|---|---|---|"]
        for url, status, length in engagement.discovered:
            recon_md.append(f"| {url} | {status} | {length} |")
        recon_md += [""]
    if engagement.recon_runs:
        recon_md += ["## Tool runs", ""]
        for run in engagement.recon_runs:
            when = time.strftime("%H:%M:%S", time.localtime(run.ts))
            recon_md += [f"### {run.tool} — `{run.target}`  ({run.category}, {when})", "",
                         "```", run.output.strip()[:20000], "```", ""]
    (base / "Recon.md").write_text("\n".join(recon_md), "utf-8")

    # ---- Site map note ----
    site_md = ["# Site map", "", f"_generated {date}_", ""]
    by_host = {}
    for r in recs:
        by_host.setdefault(r.host, []).append(r)
    for host in sorted(by_host):
        site_md += [f"## {host}", "", "| Method | Path | Status | Len |", "|---|---|---|---|"]
        seen = set()
        for r in by_host[host]:
            path = urlparse(r.url).path or "/"
            key = (r.method, path)
            if key in seen:
                continue
            seen.add(key)
            site_md.append(f"| {r.method} | {path} | {r.status if r.status is not None else ''} | {r.length if r.length is not None else ''} |")
        site_md += [""]
    (base / "Site map.md").write_text("\n".join(site_md), "utf-8")

    # ---- Findings note ----
    find_md = ["# Findings", "", f"_generated {date}_", ""]
    if findings:
        find_md += ["## Scanner findings", ""]
        order = {"Firm": 0, "High": 1, "Tentative": 2, "Info": 3}
        for f in sorted(findings, key=lambda x: order.get(getattr(x, "confidence", ""), 9)):
            find_md += [f"### {f.name} — {f.confidence}  ({f.owasp})", "",
                        f"- Point: `{f.point}`",
                        f"- Payload: `{f.payload}`",
                        f"- Evidence: {f.evidence}", ""]
            if getattr(f, "request_text", ""):
                find_md += ["```http", f.request_text.strip()[:4000], "```", ""]
    if issues:
        find_md += ["## Passive issues", "", "| Severity | Issue | URL |", "|---|---|---|"]
        sev_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        for iss in sorted(issues, key=lambda x: sev_order.get(x.severity, 9)):
            find_md.append(f"| {iss.severity} | {iss.name} | {iss.url} |")
        find_md += [""]
    (base / "Findings.md").write_text("\n".join(find_md), "utf-8")

    return str(base)


def _write_assets(base: Path, asset_map):
    """Write one note per asset plus an Assets index, cross-linked."""
    adir = base / "assets"
    adir.mkdir(parents=True, exist_ok=True)

    # index
    idx = ["# Assets", "", "_map of content_", ""]
    by_type = {}
    for a in asset_map.values():
        by_type.setdefault(a.atype, []).append(a.name)
    for atype in ("domain", "subdomain", "ip"):
        names = sorted(by_type.get(atype, []))
        if names:
            idx.append(f"## {atype.title()}s")
            idx += [f"- [[{_slug(n)}]]" for n in names]
            idx.append("")
    (base / "Assets.md").write_text("\n".join(idx), "utf-8")

    for a in asset_map.values():
        md = ["---", f"asset: {a.name}", f"type: {a.atype}"]
        if a.parent:
            md.append(f"parent: {a.parent}")
        if a.ips:
            md.append(f"ips: [{', '.join(sorted(a.ips))}]")
        md += [f"tags: [asset, {a.atype}]", "---", f"# {a.name}", ""]
        # relations
        if a.atype == "subdomain" and a.parent:
            md.append(f"- Type: subdomain of [[{_slug(a.parent)}]]")
        else:
            md.append(f"- Type: {a.atype}")
        if a.ips:
            md.append("- Resolved IPs: " + ", ".join(f"[[{_slug(ip)}]]" for ip in sorted(a.ips)))
        if a.hostnames:
            md.append("- Hostnames: " + ", ".join(f"[[{_slug(h)}]]" for h in sorted(a.hostnames)))
        if a.sources:
            md.append("- Discovered via: " + ", ".join(sorted(a.sources)))
        if a.tech:
            md.append("- Technologies: " + ", ".join(sorted(a.tech)))
        md.append("")
        if a.ports:
            md += ["## Open ports / services", "", "| Port | Proto | Service |", "|---|---|---|"]
            for port, proto, svc in sorted(a.ports):
                md.append(f"| {port} | {proto} | {svc} |")
            md.append("")
        if a.paths:
            md += ["## Paths", ""]
            for method, path, status in sorted(a.paths):
                md.append(f"- `{method}` {path}" + (f"  → {status}" if status is not None else ""))
            md.append("")
        if a.findings:
            md += ["## Findings", ""]
            for f in a.findings:
                md += [f"### {f.name} — {getattr(f,'confidence','')}  ({getattr(f,'owasp','')})",
                       f"- Point: `{getattr(f,'point','')}`",
                       f"- Payload: `{getattr(f,'payload','')}`",
                       f"- Evidence: {getattr(f,'evidence','')}", ""]
        if a.issues:
            md += ["## Passive issues", "", "| Severity | Issue |", "|---|---|"]
            for iss in a.issues:
                md.append(f"| {iss.severity} | {iss.name} |")
            md.append("")
        if a.tool_runs:
            md += ["## Tools run", ""]
            md += [f"- {t}  (see [[Recon]])" for t in sorted(a.tool_runs)]
            md.append("")
        (adir / f"{_slug(a.name)}.md").write_text("\n".join(md), "utf-8")
