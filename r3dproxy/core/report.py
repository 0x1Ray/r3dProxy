"""Export scanner findings to Markdown / JSON / SARIF, with stable fingerprints,
baseline diffing and SHA-256 evidence packs (agentshield-style)."""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from typing import List

from .. import __version__


def finding_fingerprint(f) -> str:
    """Stable id for a finding — survives re-scans, ignores volatile text so a
    baseline can report only *new* findings."""
    basis = "|".join(str(x) for x in (
        getattr(f, "plugin_id", ""), getattr(f, "owasp", ""),
        getattr(f, "name", ""), getattr(f, "point", ""),
        getattr(f, "case_label", "")))
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]


def diff_baseline(findings, baseline_path):
    """Return (new_findings, all_fingerprints). new_findings are those whose
    fingerprint is not already in the baseline file (a JSON list of fp strings)."""
    known = set()
    try:
        known = set(json.loads(Path(baseline_path).read_text("utf-8")))
    except Exception:
        known = set()
    new = [f for f in findings if finding_fingerprint(f) not in known]
    allfps = sorted({finding_fingerprint(f) for f in findings} | known)
    return new, allfps


def write_baseline(path, fingerprints):
    Path(path).write_text(json.dumps(sorted(set(fingerprints)), indent=2), "utf-8")


def findings_to_sarif(findings, target: str = "") -> str:
    """SARIF 2.1.0 — consumable by GitHub code scanning and SARIF viewers."""
    rules = {}
    results = []
    sev_map = {"Firm": "error", "High": "error", "Tentative": "warning", "Info": "note"}
    for f in findings:
        rid = getattr(f, "plugin_id", "finding")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": getattr(f, "name", rid),
                "shortDescription": {"text": getattr(f, "name", rid)},
                "properties": {"owasp": getattr(f, "owasp", "")},
            }
        results.append({
            "ruleId": rid,
            "level": sev_map.get(getattr(f, "confidence", ""), "warning"),
            "message": {"text": f"{getattr(f,'name','')}: {getattr(f,'evidence','')} "
                                f"(payload: {getattr(f,'payload','')})"},
            "partialFingerprints": {"r3dproxy/v1": finding_fingerprint(f)},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": target or getattr(f, "point", "request")}}}],
            "properties": {"confidence": getattr(f, "confidence", ""),
                           "point": getattr(f, "point", "")},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "r3dProxy", "version": __version__,
                                "informationUri": "https://github.com/0x1Ray/r3dProxy",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def evidence_pack(findings, out_dir: str, target: str = "") -> str:
    """Write each finding's request/response to files plus a SHA-256 manifest."""
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    manifest = {"tool": "r3dProxy", "version": __version__, "target": target,
                "generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "items": []}

    def _sha(data: bytes):
        return hashlib.sha256(data).hexdigest()

    for i, f in enumerate(findings, 1):
        fp = finding_fingerprint(f)
        stem = f"{i:02d}_{getattr(f,'plugin_id','finding')}_{fp}"
        files = {}
        for label, attr in (("request", "request_text"), ("response", "response_text")):
            txt = getattr(f, attr, "") or ""
            if txt:
                p = base / f"{stem}.{label}.txt"
                data = txt.encode("utf-8", "replace")
                p.write_bytes(data)
                files[label] = {"file": p.name, "sha256": _sha(data)}
        manifest["items"].append({
            "fingerprint": fp, "name": getattr(f, "name", ""),
            "confidence": getattr(f, "confidence", ""), "owasp": getattr(f, "owasp", ""),
            "point": getattr(f, "point", ""), "payload": getattr(f, "payload", ""),
            "evidence": getattr(f, "evidence", ""), "files": files,
        })
    (base / "manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
    return str(base)


def findings_to_json(findings: List) -> str:
    out = []
    for f in findings:
        out.append({
            "plugin": f.plugin_id, "name": f.name, "owasp": f.owasp,
            "confidence": f.confidence, "point": f.point, "payload": f.payload,
            "evidence": f.evidence, "case": f.case_label, "status": f.status,
            "elapsed_ms": f.elapsed_ms,
            "request": f.request_text, "response": f.response_text,
        })
    return json.dumps(out, indent=2, ensure_ascii=False)


def findings_to_markdown(findings: List, target: str = "") -> str:
    lines = ["# r3dProxy scan findings", ""]
    lines.append(f"- Target: `{target}`" if target else "")
    lines.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- Findings: {len(findings)}")
    lines.append("")
    order = {"Firm": 0, "High": 1, "Tentative": 2, "Info": 3}
    for i, f in enumerate(sorted(findings, key=lambda x: order.get(x.confidence, 9)), 1):
        lines.append(f"## {i}. {f.name} — {f.confidence}")
        lines.append("")
        lines.append(f"- **OWASP:** {f.owasp}")
        lines.append(f"- **Injection point:** `{f.point}`")
        lines.append(f"- **Case:** {f.case_label}")
        lines.append(f"- **Payload:** `{f.payload}`")
        lines.append(f"- **Evidence:** {f.evidence}")
        if f.status is not None:
            lines.append(f"- **Status:** {f.status} · {f.elapsed_ms} ms")
        lines.append("")
        if f.request_text:
            lines.append("<details><summary>Request</summary>\n")
            lines.append("```http")
            lines.append(f.request_text.strip())
            lines.append("```\n</details>")
        if f.response_text:
            lines.append("<details><summary>Response (truncated)</summary>\n")
            lines.append("```http")
            lines.append(f.response_text.strip()[:4000])
            lines.append("```\n</details>")
        lines.append("")
    return "\n".join(l for l in lines if l is not None)
