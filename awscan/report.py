"""Report rendering: JSON + Markdown + SARIF 2.1.0 artifacts."""
import json
import os
import urllib.parse
from datetime import datetime, timezone

# check name -> (CWE, SARIF level) for GitHub code-scanning-grade output
_CWE = {
    "SQL injection": ("CWE-89", "error"),
    "Time-based blind SQLi": ("CWE-89", "warning"),
    "Boolean-blind SQL extraction": ("CWE-89", "error"),
    "Reflected XSS": ("CWE-79", "error"),
    "Server-side template injection": ("CWE-1336", "error"),
    "Open redirect": ("CWE-601", "warning"),
    "Host header injection": ("CWE-640", "warning"),
    "403 bypass": ("CWE-287", "error"),
    "Security headers": ("CWE-693", "note"),
    "WAF/CDN fingerprint": ("CWE-noinfo", "note"),
    "Exposed paths": ("CWE-538", "warning"),
    "Secrets in JavaScript": ("CWE-798", "error"),
    "GraphQL introspection enabled": ("CWE-200", "warning"),
}


def build_report(target, scope_file, findings, duration_s, requests, pages=0):
    return {
        "tool": "awscan",
        "target": target,
        "scope_file": scope_file,
        "scan_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "duration_s": round(duration_s, 1),
        "requests": requests,
        "pages_crawled": pages,
        "findings": findings,
    }


def render_md(rep):
    lines = [f"# awscan report — {rep['target']}", ""]
    lines.append(f"UTC {rep['scan_utc']} · {len(rep['findings'])} findings · {rep['duration_s']}s · "
                 f"{rep['requests']} requests · {rep.get('pages_crawled', 0)} pages crawled")
    lines.append("")
    lines.append("> Results are *candidate* findings for manual validation before any report or fix.")
    lines.append("")
    for f in rep["findings"]:
        flag = " ⚠️ *manual verification required*" if f.get("manual_verify") else ""
        lines.append(f"## {f['check']}{flag}")
        for c in f.get("confidence", []):
            lines.append(f"- {c}")
        for k, v in (f.get("vectors") or {}).items():
            lines.append(f"- {k}: `{v}`")
        if "extracted" in f:
            lines.append(f"- extracted value: `{f['extracted']}`")
        for p in f.get("paths", []):
            note = " **(leak)**" if p.get("sensitive_leak") else (" (40x — bypass candidate)" if p.get("forbidden") else "")
            lines.append(f"- `{p['path']}` → {p['status']}{note}")
        for s in f.get("secrets", []):
            lines.append(f"- `{s['type']}` masked `{s['match']}` in `{s['source']}` line {s['line']}")
        lines.append("")
    if not rep["findings"]:
        lines.append("No findings. Target appears clean *for the checks run*.")
    return "\n".join(lines)


def to_sarif(rep):
    """SARIF 2.1.0: ingestable by GitHub Security tab, VS Code, defectdojo."""
    results = []
    for f in rep["findings"]:
        cwe, level = _CWE.get(f["check"], ("CWE-noinfo", "note"))
        url = next((v for k, v in (f.get("vectors") or {}).items() if isinstance(v, str) and v.startswith("http")),
                   rep["target"])
        results.append({
            "ruleId": f["check"].lower().replace(" ", "-").replace("/", "-"),
            "level": level,
            "message": {"text": "; ".join(f.get("confidence", ["finding"]))},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": url},
                "region": {"startLine": 1}}}],
            "properties": {"cwe": cwe, "manual_verify": bool(f.get("manual_verify"))},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "awscan", "version": "1.1.0",
                                "informationUri": "https://github.com/0xgetz/awscan"}},
            "results": results,
        }],
    }


def write_reports(rep, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, f"scan-{rep['scan_utc']}")
    with open(stem + ".json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2)
    with open(stem + ".md", "w", encoding="utf-8") as fh:
        fh.write(render_md(rep))
    with open(stem + ".sarif", "w", encoding="utf-8") as fh:
        json.dump(to_sarif(rep), fh, indent=2)
    return stem + ".json", stem + ".md", stem + ".sarif"
