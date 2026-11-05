"""Asset correlation — the 'brain' behind the Obsidian export.

Pulls domains, subdomains and IPs out of everything r3dProxy gathered (history,
subdomain tools, recon tool output, content discovery, findings, passive issues)
and builds one record per asset: how it was discovered, which tools touched it,
its resolved IPs, open ports/services, detected technologies, observed paths and
the findings/issues on it — cross-linked (subdomain↔parent, host↔IP).
"""
from __future__ import annotations
import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlparse

from . import httptext

DOMAIN = "domain"
SUBDOMAIN = "subdomain"
IP = "ip"

_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}\b", re.I)
_NMAP_PORT = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)", re.M)
_NMAP_HOST = re.compile(r"Nmap scan report for (\S+?)(?:\s+\(([\d.]+)\))?$", re.M)


def _valid_ip(s: str) -> bool:
    m = _IP_RE.fullmatch(s)
    if not m:
        return False
    return all(0 <= int(o) <= 255 for o in m.groups())


def _extract_ips(text: str):
    out = set()
    for m in _IP_RE.finditer(text or ""):
        if all(0 <= int(o) <= 255 for o in m.groups()):
            ip = m.group(0)
            if not ip.startswith("0.") and ip != "255.255.255.255":
                out.add(ip)
    return out


@dataclass
class Asset:
    name: str
    atype: str
    parent: str = ""
    ips: set = field(default_factory=set)
    hostnames: set = field(default_factory=set)   # for IP assets
    ports: list = field(default_factory=list)     # (port, proto, service)
    tech: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    paths: set = field(default_factory=set)       # (method, path, status)
    tool_runs: set = field(default_factory=set)
    findings: list = field(default_factory=list)
    issues: list = field(default_factory=list)


def _registered(host: str, scope) -> str:
    """Return the scope domain that `host` is a subdomain of, if any."""
    host = (host or "").lower()
    for s in scope or []:
        s = s.lower().strip()
        if s and (host == s or host.endswith("." + s)):
            return s
    # fallback: last two labels
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _classify(host: str, scope) -> str:
    if _valid_ip(host):
        return IP
    reg = _registered(host, scope)
    return DOMAIN if host.lower() == reg else SUBDOMAIN


def _in_scope(host: str, scope) -> bool:
    host = (host or "").lower()
    if not scope:
        return True
    for s in scope:
        s = s.lower().strip()
        if s and (s in host or host.endswith("." + s) or host == s):
            return True
    return False


class Correlator:
    def __init__(self, scope):
        self.scope = scope or []
        self.assets: Dict[str, Asset] = {}

    def _get(self, name, atype=None):
        name = name.lower().strip().rstrip(".")
        if not name:
            return None
        a = self.assets.get(name)
        if a is None:
            at = atype or _classify(name, self.scope)
            a = Asset(name=name, atype=at)
            if at == SUBDOMAIN:
                a.parent = _registered(name, self.scope)
            self.assets[name] = a
        return a

    def add_host(self, host, source):
        a = self._get(host)
        if a:
            a.sources.add(source)
        return a

    def ingest_history(self, store):
        for r in store.all():
            if not _in_scope(r.host, self.scope):
                continue
            a = self.add_host(r.host, "proxy history")
            if a:
                path = urlparse(r.url).path or "/"
                a.paths.add((r.method, path, r.status))

    def ingest_subdomains(self, subs):
        for s in subs or []:
            if _in_scope(s, self.scope):
                a = self._get(s, SUBDOMAIN)
                if a:
                    a.sources.add("subdomain tool")

    def ingest_discovered(self, discovered):
        for url, status, length in discovered or []:
            host = urlparse(url).netloc.split(":")[0]
            if not _in_scope(host, self.scope):
                continue
            a = self.add_host(host, "content discovery")
            if a:
                a.paths.add(("GET", urlparse(url).path or "/", status))

    def ingest_findings(self, findings):
        for f in findings or []:
            host = self._host_from_request(getattr(f, "request_text", ""))
            if host and _in_scope(host, self.scope):
                a = self.add_host(host, "scanner")
                if a:
                    a.findings.append(f)

    def ingest_issues(self, issues):
        for iss in issues or []:
            host = urlparse(iss.url).netloc.split(":")[0]
            if host and _in_scope(host, self.scope):
                a = self.add_host(host, "passive audit")
                if a:
                    a.issues.append(iss)

    def ingest_recon(self, recon_runs):
        for run in recon_runs or []:
            target_host = self._host_from_target(run.target)
            ta = self.add_host(target_host, f"{run.tool}") if target_host else None
            if ta:
                ta.tool_runs.add(run.tool)
            out = run.output or ""
            # hostnames in scope
            for h in _HOST_RE.findall(out):
                if _in_scope(h, self.scope):
                    a = self._get(h)
                    if a:
                        a.sources.add(run.tool)
                        a.tool_runs.add(run.tool)
            # IPs
            ips = _extract_ips(out)
            # nmap host→IP mapping
            host_ip = {}
            for m in _NMAP_HOST.finditer(out):
                hn, ip = m.group(1), m.group(2)
                if ip:
                    host_ip[hn.lower()] = ip
            # ports
            ports = [(int(p), proto, svc) for p, proto, _st, svc in _NMAP_PORT.findall(out)]
            # attach ports to target asset and its IPs
            if ta and ports:
                for pt in ports:
                    if pt not in ta.ports:
                        ta.ports.append(pt)
            for ip in ips:
                ia = self._get(ip, IP)
                if ia:
                    ia.sources.add(run.tool)
                    if ta:
                        ia.hostnames.add(ta.name)
                        ta.ips.add(ip)
                    if ports:
                        for pt in ports:
                            if pt not in ia.ports:
                                ia.ports.append(pt)
            for hn, ip in host_ip.items():
                if _in_scope(hn, self.scope):
                    a = self._get(hn)
                    ia = self._get(ip, IP)
                    if a and ia:
                        a.ips.add(ip); ia.hostnames.add(a.name)
            # tech (whatweb / httpx style)
            for tech in self._extract_tech(out):
                if ta:
                    ta.tech.add(tech)

    def resolve_dns(self):
        for a in list(self.assets.values()):
            if a.atype in (DOMAIN, SUBDOMAIN) and not a.ips:
                try:
                    socket.setdefaulttimeout(2.0)
                    ip = socket.gethostbyname(a.name)
                    a.ips.add(ip)
                    ia = self._get(ip, IP)
                    if ia:
                        ia.hostnames.add(a.name)
                        ia.sources.add("DNS resolve")
                except Exception:
                    pass

    # ---- helpers ----
    def _host_from_request(self, request_text):
        try:
            _s, headers, _b = httptext.split_message(request_text)
            for k, v in headers:
                if k.lower() == "host":
                    return v.strip().split(":")[0]
        except Exception:
            pass
        return ""

    def _host_from_target(self, target):
        target = (target or "").strip()
        if not target:
            return ""
        if "://" in target:
            return urlparse(target).netloc.split(":")[0]
        return target.split("/")[0].split(":")[0]

    def _extract_tech(self, out):
        tech = set()
        noise = {"Country", "IP", "Title", "Email", "UncommonHeaders", "RedirectLocation",
                 "HTML5", "Script", "Meta", "Via", "Cookies", "HttpOnly", "Strict-Transport-Security",
                 "X-Frame-Options", "X-XSS-Protection", "X-UA-Compatible"}
        # whatweb: tokens like Apache[2.4.1], PHP[7.4], jQuery
        for m in re.finditer(r"\b([A-Z][A-Za-z0-9.+_-]{1,30})\[", out):
            t = m.group(1)
            if t not in noise:
                tech.add(t)
        # httpx tech-detect bracket list: [nginx,PHP,Cloudflare]
        for m in re.finditer(r"\[([a-zA-Z0-9 ,._+-]{2,80})\]", out):
            inner = m.group(1)
            if "," in inner and not inner.replace(",", "").isdigit():
                for t in inner.split(","):
                    t = t.strip()
                    if t and not t.isdigit() and len(t) <= 30:
                        tech.add(t)
        return tech


def correlate(scope, store, recon_runs, subdomains, discovered, findings, issues,
              resolve=True) -> Dict[str, Asset]:
    c = Correlator(scope)
    c.ingest_history(store)
    c.ingest_subdomains(subdomains)
    c.ingest_discovered(discovered)
    c.ingest_findings(findings)
    c.ingest_issues(issues)
    c.ingest_recon(recon_runs)
    if resolve:
        c.resolve_dns()
    return c.assets
