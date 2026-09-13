# awscan

Automated web vulnerability scanner for **authorized security testing** — zero dependencies, Python 3.9+, stdlib only.

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇮🇩 [Bahasa Indonesia](README.id.md) · 🇨🇳 [中文](README.zh-CN.md)

## What it does

Point it at a URL with a parameter placeholder and it runs a battery of proven checks:

| Check | Technique |
|---|---|
| SQL injection | DBMS error-marker sniff + TRUE/FALSE differential oracle — never raw length deltas |
| Boolean-blind extraction | char-by-char recovery via the confirmed oracle (portable `substr()` equality, works on SQLite/MySQL/PostgreSQL shapes) |
| Reflected XSS | byte-identical reflection of a unique probe (quote not encoded), then an event-handler payload confirmation |
| Open redirect | param swap to an external canary host, verified on the `Location` header |
| Security headers | missing CSP / XFO / HSTS / XCTO + server version disclosure |
| Exposed paths | conventional sensitive paths (`.env`, `.git/HEAD`, backups) with content-aware leak confirmation |

Every finding carries the exact vector URLs used, so you can reproduce or extend it by hand. Reports land as JSON + Markdown.

## The scope gate

**awscan refuses to send a single request to a host that is not listed in your scope file.** This is a hard gate, not a flag:

```
$ python3 -m awscan.cli --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file — refusing to send any request.
```

Add hosts only when you hold written/program authorization: your own assets, a lab, or a bug-bounty program's declared scope.

## Quick start

```bash
git clone https://github.com/0xgetz/awscan && cd awscan
cp scope.example.txt my-scope.txt        # edit: add your authorized hosts

# 1) self-test on the bundled deliberately-vulnerable lab (loopback only)
python3 lab_server.py --port 8777 &
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"
# → reports/scan-*.md with 5 findings incl. extracted secret

# 2) production scan (respect the defaults: delay ≥ 1s)
python3 -m awscan.cli --target "https://in-scope.example.com/search?q=TEST" --scope my-scope.txt
```

`TEST` in the target URL is the injection placeholder — the scanner swaps it per payload.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--target` | required | URL embedding the `TEST` placeholder param value |
| `--scope` | `scope.example.txt` | authorized-hosts file (`*.domain` = subdomain wildcard) |
| `--delay` | `1.0` | seconds between requests (keep ≥ 1 against production) |
| `--budget` | `900` | wall-clock seconds before SIGALRM hard-exit (a pacing sleep inside a hung socket can't outrun cooperative checks — this backstop flushes and leaves) |
| `--extract-sql` | off | boolean-blind demo of one `SELECT` expression |
| `--out` | `reports` | report output directory |

## Confidence model (anti self-fool)

A changed byte-count is never a finding. Injection claims require a DBMS error marker **or** a TRUE/FALSE differential on a stable state anchor (row count). A WAF-escaping payload that leaves the state anchor unchanged is *not vulnerable* — the tool says so instead of drowning you in raw-scanner noise. This mirrors the manual-validation discipline bug-bounty programs demand.

## Development

```bash
python3 -m unittest discover -s test   # 17 tests, fully offline (spawn lab, ephemeral port)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules that keep this tool trustworthy.

## Responsible use

- Authorized targets only — the scope gate exists to make the honest path the easy path.
- Results are *candidate* findings; validate manually before reporting or fixing.
- The bundled `lab_server.py` is deliberately insecure and binds loopback only. Never deploy it.

## License

MIT — see [LICENSE](LICENSE).
