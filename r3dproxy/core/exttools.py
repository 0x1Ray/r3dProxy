"""Registry of external Linux security tools r3dProxy can drive.

r3dProxy does not reimplement these — it detects what's installed, builds the
right command line, runs it and streams the output. A setup script installs the
missing ones. Everything here is data + command builders; the GUI runs them.
"""
from __future__ import annotations
import shutil
from dataclasses import dataclass, field
from typing import Callable, List, Optional

SCANNER = "scanner"
FUZZER = "fuzzer"
SUBDOMAIN = "subdomain"


@dataclass
class Tool:
    id: str
    name: str
    binary: str
    category: str
    mode: str           # "active" / "passive" / "" (for fuzzers/subdomain)
    desc: str
    install: str        # human hint, e.g. "apt install nikto" / "go install …"
    build: Callable     # (ctx) -> List[str] argv

    def path(self) -> Optional[str]:
        return shutil.which(self.binary)

    def installed(self) -> bool:
        return self.path() is not None


@dataclass
class RunCtx:
    target: str = ""        # host or URL
    domain: str = ""        # for subdomain tools
    wordlist: str = ""      # path to a wordlist file (fuzzers)
    extra: str = ""         # extra user args (shlex-split by caller)


def _split_extra(ctx: RunCtx):
    import shlex
    return shlex.split(ctx.extra) if ctx.extra.strip() else []


def target_host(t: str) -> str:
    """Bare hostname/IP from a host, host:port, or full URL (for nmap/testssl)."""
    from urllib.parse import urlparse
    t = (t or "").strip()
    netloc = urlparse(t).netloc if "://" in t else t.split("/")[0]
    netloc = netloc.split("@")[-1]          # strip creds
    if netloc.startswith("["):              # IPv6 literal [::1]:80
        return netloc[1:].split("]")[0]
    return netloc.split(":")[0]             # strip port


def target_url(t: str) -> str:
    """scheme://host[:port] origin from a host or URL (for nikto/nuclei/… )."""
    from urllib.parse import urlparse
    t = (t or "").strip()
    if "://" in t:
        p = urlparse(t)
        return f"{p.scheme}://{p.netloc}"
    host = t.split("/")[0]
    return "https://" + host


# ---------------- scanners (active / passive) ----------------
# host-based tools get a bare hostname; url-based tools get a scheme://host origin
def _nmap(c):      return ["nmap", "-sV", "-T4", target_host(c.target), *_split_extra(c)]
def _nikto(c):     return ["nikto", "-h", target_url(c.target), *_split_extra(c)]
def _nuclei(c):    return ["nuclei", "-u", target_url(c.target), "-nc", *_split_extra(c)]
def _whatweb(c):   return ["whatweb", "--color=never", target_url(c.target), *_split_extra(c)]
def _wafw00f(c):   return ["wafw00f", target_url(c.target), *_split_extra(c)]
def _testssl(c):   return ["testssl.sh", "--color", "0", target_host(c.target), *_split_extra(c)]
def _httpx(c):     return ["httpx", "-u", target_url(c.target), "-nc", "-title", "-status-code", "-tech-detect", *_split_extra(c)]
def _wpscan(c):    return ["wpscan", "--url", target_url(c.target), "--no-banner", *_split_extra(c)]
def _nmapvuln(c):  return ["nmap", "-sV", "--script", "vuln", "-T4", target_host(c.target), *_split_extra(c)]


# ---------------- directory / content fuzzers ----------------
def _ffuf(c):
    url = c.target if "FUZZ" in c.target else c.target.rstrip("/") + "/FUZZ"
    return ["ffuf", "-u", url, "-w", c.wordlist, "-mc", "200,204,301,302,307,401,403,405", *_split_extra(c)]
def _gobuster(c):  return ["gobuster", "dir", "-u", c.target, "-w", c.wordlist, "-q", *_split_extra(c)]
def _feroxbuster(c): return ["feroxbuster", "-u", c.target, "-w", c.wordlist, "-q", *_split_extra(c)]
def _dirb(c):      return ["dirb", c.target, c.wordlist, "-S", *_split_extra(c)]
def _wfuzz(c):
    url = c.target if "FUZZ" in c.target else c.target.rstrip("/") + "/FUZZ"
    return ["wfuzz", "-w", c.wordlist, "--hc", "404", url, *_split_extra(c)]
def _dirsearch(c): return ["dirsearch", "-u", c.target, *(["-w", c.wordlist] if c.wordlist else []), *_split_extra(c)]


# ---------------- subdomain discovery ----------------
def _subfinder(c):   return ["subfinder", "-d", target_host(c.domain), "-silent", *_split_extra(c)]
def _assetfinder(c): return ["assetfinder", "--subs-only", target_host(c.domain), *_split_extra(c)]
def _amass(c):       return ["amass", "enum", "-passive", "-d", target_host(c.domain), *_split_extra(c)]
def _findomain(c):   return ["findomain", "-t", target_host(c.domain), "-q", *_split_extra(c)]
def _sublist3r(c):   return ["sublist3r", "-d", target_host(c.domain), *_split_extra(c)]


TOOLS: List[Tool] = [
    # scanners
    Tool("whatweb", "WhatWeb", "whatweb", SCANNER, "passive", "Fingerprint tech stack", "apt install whatweb", _whatweb),
    Tool("wafw00f", "wafw00f", "wafw00f", SCANNER, "passive", "Detect WAF", "pipx install wafw00f", _wafw00f),
    Tool("httpx", "httpx", "httpx", SCANNER, "passive", "Probe URLs (title/status/tech)", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", _httpx),
    Tool("testssl", "testssl.sh", "testssl.sh", SCANNER, "passive", "TLS/SSL audit", "git clone github.com/drwetter/testssl.sh", _testssl),
    Tool("nmap", "Nmap (service)", "nmap", SCANNER, "active", "Port/service scan", "apt install nmap", _nmap),
    Tool("nmapvuln", "Nmap (vuln scripts)", "nmap", SCANNER, "active", "NSE vuln scripts", "apt install nmap", _nmapvuln),
    Tool("nikto", "Nikto", "nikto", SCANNER, "active", "Web server scanner", "apt install nikto", _nikto),
    Tool("nuclei", "Nuclei", "nuclei", SCANNER, "active", "Templated vuln scanner", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", _nuclei),
    Tool("wpscan", "WPScan", "wpscan", SCANNER, "active", "WordPress scanner", "gem install wpscan", _wpscan),
    # fuzzers
    Tool("ffuf", "ffuf", "ffuf", FUZZER, "", "Fast web fuzzer (FUZZ keyword)", "go install github.com/ffuf/ffuf/v2@latest", _ffuf),
    Tool("gobuster", "gobuster", "gobuster", FUZZER, "", "Directory/file brute forcer", "go install github.com/OJ/gobuster/v3@latest", _gobuster),
    Tool("feroxbuster", "feroxbuster", "feroxbuster", FUZZER, "", "Recursive content discovery", "apt install feroxbuster", _feroxbuster),
    Tool("dirb", "dirb", "dirb", FUZZER, "", "Classic directory scanner", "apt install dirb", _dirb),
    Tool("wfuzz", "wfuzz", "wfuzz", FUZZER, "", "Web fuzzer (FUZZ keyword)", "apt install wfuzz", _wfuzz),
    Tool("dirsearch", "dirsearch", "dirsearch", FUZZER, "", "Path scanner", "pipx install dirsearch", _dirsearch),
    # subdomain
    Tool("subfinder", "subfinder", "subfinder", SUBDOMAIN, "", "Passive subdomain enum", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", _subfinder),
    Tool("assetfinder", "assetfinder", "assetfinder", SUBDOMAIN, "", "Find subdomains", "go install github.com/tomnomnom/assetfinder@latest", _assetfinder),
    Tool("amass", "amass", "amass", SUBDOMAIN, "", "In-depth subdomain enum", "apt install amass", _amass),
    Tool("findomain", "findomain", "findomain", SUBDOMAIN, "", "Fast subdomain finder", "see github.com/findomain/findomain", _findomain),
    Tool("sublist3r", "Sublist3r", "sublist3r", SUBDOMAIN, "", "Subdomain enumeration", "pipx install sublist3r", _sublist3r),
]

_BY_ID = {t.id: t for t in TOOLS}


def get(tool_id: str) -> Tool:
    return _BY_ID[tool_id]


def by_category(category: str) -> List[Tool]:
    return [t for t in TOOLS if t.category == category]


def status():
    """Return list of (Tool, installed_bool)."""
    return [(t, t.installed()) for t in TOOLS]


def missing() -> List[Tool]:
    return [t for t in TOOLS if not t.installed()]


def build(tool_id: str, ctx: RunCtx) -> List[str]:
    return _BY_ID[tool_id].build(ctx)
