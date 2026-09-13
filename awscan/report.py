"""Report rendering: JSON + Markdown artifacts."""
import json
import os
from datetime import datetime, timezone


def build_report(target, scope_file, findings, duration_s, requests):
    return {
        "tool": "awscan",
        "target": target,
        "scope_file": scope_file,
        "scan_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "duration_s": round(duration_s, 1),
        "requests": requests,
        "findings": findings,
    }


def render_md(rep):
    lines = [f"# awscan report — {rep['target']}", ""]
    lines.append(f"UTC {rep['scan_utc']} · {len(rep['findings'])} findings · {rep['duration_s']}s · {rep['requests']} requests")
    lines.append("")
    lines.append("> Results are *candidate* findings for manual validation before any report or fix.")
    lines.append("")
    for f in rep["findings"]:
        lines.append(f"## {f['check']}")
        for c in f.get("confidence", []):
            lines.append(f"- {c}")
        for k, v in (f.get("vectors") or {}).items():
            lines.append(f"- {k}: `{v}`")
        if "extracted" in f:
            lines.append(f"- extracted value: `{f['extracted']}`")
        for p in f.get("paths", []):
            lines.append(f"- `{p['path']}` → {p['status']}" + (" **(leak)**" if p["sensitive_leak"] else ""))
        lines.append("")
    if not rep["findings"]:
        lines.append("No findings. Target appears clean *for the checks run*.")
    return "\n".join(lines)


def write_reports(rep, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, f"scan-{rep['scan_utc']}")
    with open(stem + ".json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2)
    with open(stem + ".md", "w", encoding="utf-8") as fh:
        fh.write(render_md(rep))
    return stem + ".json", stem + ".md"
