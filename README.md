# r3dProxy

[![CI](https://github.com/0x1Ray/r3dProxy/actions/workflows/ci.yml/badge.svg)](https://github.com/0x1Ray/r3dProxy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-e11d2a.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

An AI-assisted intercepting web proxy with a GUI — a lightweight, hackable
alternative to Burp Suite for **authorized** web application security testing
(bug bounty / pentests you have permission to run).

Built on [mitmproxy](https://mitmproxy.org/) (proxy engine + TLS CA) and
[PySide6](https://doc.qt.io/qtforpython/) (GUI), with an Claude-powered
assistant that analyzes a response and suggests how to modify a request when an
input or payload gets rejected.

> Use it only against systems you own or are explicitly authorized to test.

## Features

- **Intercepting proxy** (HTTP + HTTPS via an auto-generated CA).
- **Intercept queue** — pause requests, edit them freely, then Forward / Drop /
  Forward-all.
- **HTTP history** — searchable table (plus **deep** regex search across full
  request+response bodies) with request/response viewers, colored status codes,
  right-click → send to Repeater / Intruder / Scanner / Sequencer / AI / CSRF PoC.
- **Repeater** — multi-tab; edit a request and resend it, inspect the response,
  one click to the AI assistant. Optional **raw-socket** mode.
- **Intruder** — four attack types (sniper, battering ram, pitchfork, cluster
  bomb) over one or more `§…§` positions, per-position payload sets, wordlists,
  **grep-extract** (pull a regex match into a sortable column), and optional
  raw-socket mode.
- **Scanner (OWASP plugins)** — run one-vulnerability-per-plugin checks against a
  single request at a `§…§` point. Ten built-in plugins with PortSwigger-style
  payload variations and per-vuln detection tuned to cut false positives.
- **Passive auditing (Issues)** — while you browse, every response is checked for
  missing security headers, weak cookie flags, reflected input, verbose
  errors/stack traces, version/internal-IP disclosure and risky CORS — surfaced,
  de-duplicated, in the **Issues** tab.
- **Raw-socket sender** — byte-exact requests (no header reordering / injection),
  which is what makes CRLF, CORS/Origin and malformed-request tests reliable.
- **Wordlists** — built-in lightweight lists (XSS, SQLi, LFI, command injection,
  SSTI, SSRF/redirect, fuzz chars, …) plus your own, added from the GUI or the
  terminal.
- **AI assistant** — paste/send a request + response; Claude diagnoses *why* it
  was rejected (WAF, validation, encoding, Content-Type, CSRF, …) and proposes
  ready-to-send variants. One click turns its suggestions into a payload set
  loaded straight into **Intruder** (*Payloads → Intruder*).
- **Sequencer** — estimate token randomness (session IDs, CSRF/reset tokens):
  paste tokens or capture one from repeated requests, and get per-position
  entropy, duplicate/sequence detection and a plain verdict.
- **Tools** — Decoder/Encoder (URL, Base64, Hex, HTML, JWT, pretty JSON/XML), a
  response **Comparer** (coloured line diff), and a **CSRF PoC generator**
  (auto-submitting form or fetch PoC from any request). Right-click any editor →
  *Pretty-print body*.
- **OAST** — built-in out-of-band callback listener with token URLs to confirm
  blind SSRF/XXE/RCE; set a public base URL (VPS / interactsh) for internet
  callbacks. The Scanner uses it automatically (*use OAST*) to upgrade blind
  SSRF/XXE/command-injection findings to **Firm** when a callback arrives.
- **Sessions** — save/restore HTTP history and Repeater tabs to JSON.
- **Reports** — export Scanner findings to Markdown or JSON for write-ups.
- **Target site map** — a host → path tree built from history, with request/
  response viewers and right-click **scope** control; send any node to
  Repeater/Scanner/Intruder/AI.
- **Content discovery** — brute-force hidden paths/files on a host with a
  wordlist and extension list, with soft-404 calibration; add found paths to the
  site map. Launched from the Target tab.
- **Recon (external Linux tools)** — r3dProxy drives the standard tools instead
  of reinventing them: **scanners** (nmap, nikto, nuclei, whatweb, wafw00f,
  httpx, testssl, wpscan), **directory fuzzing** (ffuf, gobuster, feroxbuster,
  dirb, wfuzz, dirsearch) and **subdomain discovery** (subfinder, amass,
  assetfinder, findomain, sublist3r) — with live output, installed-tool
  detection and a one-click installer (`scripts/install_tools.sh`).
- **Engagement export (Obsidian)** — export everything gathered on a scoped
  target — footprinting, recon tool runs, subdomains, site map and findings
  (scanner + passive) — as linked Markdown notes into an Obsidian vault.
- **Match & Replace** — regex rules auto-rewriting requests/responses.
- **Scope** — restrict interception (and passive auditing) to chosen hosts.
- **Extensible** — drop your own wordlists and scanner plugins into
  `~/.r3dproxy/`.
- **Dark "hawk" theme.**

## Screenshots

| Proxy & history | Scanner (OWASP plugins) |
|---|---|
| ![Proxy and HTTP history](docs/img/01-proxy-history.png) | ![Scanner](docs/img/02-scanner.png) |

| AI assistant | Intruder |
|---|---|
| ![AI assistant](docs/img/03-ai.png) | ![Intruder](docs/img/04-intruder.png) |

| Target site map | Passive issues |
|---|---|
| ![Target site map](docs/img/05-target.png) | ![Issues](docs/img/06-issues.png) |

## Scanner — OWASP plugins

Open the **Scanner** tab (or right-click a request in history → *Send to
Scanner*), wrap the value you want to test in `§…§`, tick the plugins to run,
and **Scan**. Findings show plugin, OWASP category, confidence
(Firm/High/Tentative/Info), the injection point and the evidence; click one to
see the exact request/response, or right-click to push it to Repeater/AI.

| Plugin | OWASP (2021) | Detection |
|---|---|---|
| SQL Injection | A03 Injection | DB error signatures, boolean TRUE/FALSE diff vs baseline, confirmed time-based |
| Cross-Site Scripting | A03 Injection | unique-token reflection with metachars surviving unencoded in an HTML response |
| OS Command Injection | A03 Injection | confirmed time-based across shell separators |
| Server-Side Template Injection | A03 Injection | arithmetic eval (e.g. `1337*7`→`9359`) absent from baseline |
| Path Traversal / LFI | A01 Broken Access Control | `/etc/passwd` and `win.ini` signatures, encoding bypasses |
| SSRF | A10 SSRF | cloud-metadata/internal signatures; else flagged Tentative for OAST confirmation |
| XXE | A05 Misconfiguration | external-entity file read returned in the response |
| Open Redirect | A01 Broken Access Control | off-site `Location` host with filter-bypass variants |
| CRLF / Header Injection | A03 Injection | injected header/cookie actually appears in the response |
| CORS Misconfiguration | A05 Misconfiguration | `ACAO` reflects attacker `Origin`, worse with `credentials:true` |

Detection runs a baseline and a benign control probe first, requires timing
findings to be confirmed, and compares against the baseline — so a slow endpoint
or an error page that already existed won't light up as a bug. SSRF stays
Tentative unless an internal signature leaks, because it genuinely needs an
out-of-band (Collaborator-style) host to confirm.

### Write your own plugin

Drop a `.py` file in `~/.r3dproxy/plugins/` that defines `plugin = YourPlugin()`
(or `PLUGINS = [...]`). A `plugin_template.py` is included in the repo:

```python
from r3dproxy.core.plugins.base import Plugin, Case, sub_marker, point_label, FIRM

class MyCheck(Plugin):
    id = "mycheck"; name = "My Check"; owasp = "A03:2021 Injection"
    description = "what it tests"
    def build_cases(self, base_text, marker):
        return [Case("probe", sub_marker(base_text, "PAYLOAD"), "PAYLOAD")]
    def detect(self, case, resp, engine):
        if resp.ok and "signature" in resp.body:
            return self._finding(case, resp, FIRM, "found signature", point_label(engine.base_text))

plugin = MyCheck()
```

## Install

Requires Python 3.10+.

```bash
cd r3dproxy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

On Linux you may also need the Qt runtime libs (usually pulled in by PySide6).
If the window fails to start with an `xcb` plugin error, install your distro's
`libxcb` packages (e.g. `sudo apt install libxcb-cursor0`).

## HTTPS interception — install the CA

1. Start r3dProxy once and send one HTTPS request through it so the CA is
   generated at `~/.r3dproxy/ca/mitmproxy-ca-cert.pem`.
2. Point your browser/system at the proxy (default `127.0.0.1:8080`). FoxyProxy
   or your OS network settings both work.
3. Trust the CA:
   - **Firefox:** Settings → Privacy & Security → Certificates → View
     Certificates → Authorities → Import → select the `.pem` → trust for
     websites.
   - **System (Debian/Ubuntu):**
     ```bash
     sudo cp ~/.r3dproxy/ca/mitmproxy-ca-cert.pem \
        /usr/local/share/ca-certificates/r3dproxy.crt
     sudo update-ca-certificates
     ```
   - Or use **Settings → CA cert → Export** inside the app.

## Browser setup (FoxyProxy)

r3dProxy is a standard HTTP proxy, so any proxy switcher works — no custom
browser extension needed. **FoxyProxy** (or Proxy SwitchyOmega) is the usual
choice. The toolbar's **Proxy setup** button shows the exact address to use,
copies it, exports a ready-to-import FoxyProxy config, and exports the CA cert.

1. Install FoxyProxy (Firefox or Chrome).
2. Add a proxy: **Type** HTTP, **Host** `127.0.0.1`, **Port** `8080` (match your
   listen port), name it `r3dProxy` — or import the config from *Proxy setup*.
3. Toggle it on, browse the target, and watch **HTTP history** fill up.
4. For HTTPS, install the CA once (see above).

You can also point your OS network settings at `127.0.0.1:8080`, but a
browser-scoped switcher keeps the rest of your machine off the proxy.

## External recon tools

The **Recon** tab runs real Linux security tools as subprocesses — it does not
reimplement them. Click **Check tools** to see what's installed, or **Install
tools…** to run the bundled setup script:

```bash
bash scripts/install_tools.sh            # apt + go + pip (apt needs sudo)
bash scripts/install_tools.sh --nosudo   # go/pip only
bash scripts/install_tools.sh --list     # show status
```

It installs what it can via `apt`, `go install` and `pipx`/`pip`; a few tools
(testssl.sh, findomain, wpscan) have manual one-liners printed at the end. Go
tools land in `$(go env GOPATH)/bin`, so make sure that's on your `PATH`.

## Engagement notes (Obsidian)

Set a scope (Target tab → right-click a host → *Add to scope*), work the target,
then toolbar **Export notes** writes a linked note set into an Obsidian vault:

```
<vault>/r3dProxy/<target>/
  <target>.md    overview + index + hosts
  Recon.md       subdomains, discovered content, tool-run output
  Site map.md    hosts and paths
  Findings.md    scanner findings + passive issues
```

Everything is plain Markdown with `[[wikilinks]]`, so it opens directly in
Obsidian (or any Markdown editor).

## AI assistant setup

The assistant uses the Anthropic API. Provide a key via the environment
(preferred):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python run.py
```

Or paste a key under **Settings → AI**. Set the model there too — the default is
`claude-sonnet-4-5`; change it to whatever model id your account uses. No key
is required for the proxy/repeater/intruder features; only the AI tab needs one.

## Wordlists

Built-in lists ship inside the app (shown with a ★ in the Intruder wordlist
dropdown). Your own lists live as plain `.txt` files (one payload per line,
`#` comments and blank lines ignored) under:

```
~/.r3dproxy/wordlists/
```

Add them two ways:

- **GUI:** Intruder tab → *Import…* (copies a file in), or *Save as…* (saves the
  current payload box as a reusable list). They appear with a ◆ prefix.
- **Terminal:** just drop files into the folder and hit the ⟳ button:
  ```bash
  mkdir -p ~/.r3dproxy/wordlists
  cp /path/to/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt ~/.r3dproxy/wordlists/
  ```

## Typical workflow

1. Proxy your browser through r3dProxy, browse the target.
2. Find an interesting request in **HTTP history** → right-click → **Send to
   Repeater**.
3. Try a payload. If it's rejected (403, 400, validation error), click **→ AI**
   to get bypass suggestions.
4. Turn a suggestion into a **§…§** marker in **Intruder**, load a wordlist, and
   fire the whole set to see which variant passes.

## Layout

```
run.py                     launcher
r3dproxy/
  config.py                settings (~/.r3dproxy/settings.json)
  core/
    proxy_engine.py        mitmproxy wrapper + Qt bridge (intercept/forward/drop)
    flowstore.py           in-memory flow store
    httptext.py            raw HTTP <-> editable text
    sender.py              standalone request sender (requests-based)
    raw_sender.py          byte-exact raw-socket sender
    intruder.py            attack types + grep-extract
    passive.py             passive audit checks
    sequencer.py           token randomness analysis
    codec.py / csrf.py     decoder/comparer + CSRF PoC
    wordlists.py           built-in + user wordlists
    oast.py / oast_registry.py   OAST listener + shared callback registry
    ai_client.py           Claude analysis + payload generation
    plugins/               scanner plugin framework + 10 OWASP built-ins
  gui/
    main_window.py         window, toolbar, cross-tab actions
    proxy_tab.py           intercept queue + history (deep search)
    target_tab.py          site map tree + scope
    repeater_tab.py        repeater
    intruder_tab.py        4 attack types, payload sets, grep-extract
    scanner_tab.py         OWASP scanner
    sequencer_tab.py       token analysis
    issues_tab.py          passive issues
    tools_tab.py           decoder / comparer / CSRF PoC
    oast_tab.py            OAST listener UI
    ai_tab.py              AI assistant
    discovery_dialog.py    content discovery
    proxy_setup_dialog.py  FoxyProxy / CA helper
    settings_dialog.py     settings
    editor.py / theme.py / workers.py
```

## Notes & roadmap ideas

- Repeater/Intruder default to the `requests` sender (robust); tick **raw
  socket** for byte-exact control. The Scanner always uses the raw sender.
- No persistent session save yet (history is in-memory per run).
- HTTP/2 flows are captured; editing is done at the HTTP/1 text level.
- SSRF/OAST: wiring in a Collaborator-style callback host would upgrade several
  Tentative checks to Firm.

## License

MIT — see `LICENSE`. Test only systems you own or are explicitly authorized to
assess.
