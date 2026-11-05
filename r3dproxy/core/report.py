"""Export scanner findings to Markdown or JSON (bug-bounty-friendly)."""
from __future__ import annotations
import json
import time
from typing import List


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
