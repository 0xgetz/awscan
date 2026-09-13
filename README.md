# awscan

Automated web vulnerability scanner for **authorized security testing** — zero dependencies, Python 3.9+, stdlib only.

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇮🇩 [Bahasa Indonesia](README.id.md) · 🇨🇳 [中文](README.zh-CN.md)

## What it does

Give it a URL — or just the site root with `--crawl` and it discovers every injectable parameter itself — and it runs a battery of proven checks:

| Check | Technique |
|---|---|
| Same-origin crawl | BFS link/form/JS discovery of pages + every GET parameter; forbidden (401/403) paths auto-collected for the bypass battery |
| SQL injection | DBMS error-marker sniff + TRUE/FALSE differential oracle — never raw length deltas |
| Boolean-blind extraction | char-by-char recovery via the confirmed oracle (portable `substr()` equality, works on SQLite/MySQL/PostgreSQL shapes) |
| Time-based blind SQLi | stacked-delay payloads (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`) vs. median baseline latency — always flagged for manual recheck |
| Reflected XSS | byte-identical reflection of a unique probe (quote not encoded), then an event-handler payload confirmation |
| SSTI | arithmetic template probes (`{{7*7}}`-class, `${{…}}`, ERB, Freemarker) — a finding requires the probe to come back **computed**, never echoed |
| Open redirect | param swap to an external canary host, verified on the `Location` header |
| Host header injection | canary `Host:` header reflected in the response body/links — the password-reset-poisoning class |
| 403/401 bypass battery | path tricks (`;/`, `..;`, `%2e`, double-slash) + header tricks (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) against every forbidden path found |
| GraphQL | read-only `__schema` introspection probe on common endpoints |
| Secrets in JS bundles | sweep of crawled `.js` for AWS/GCP/GitHub/Stripe/JWT/private-key patterns — **masked in reports**, never full secrets on disk |
| Security headers + cookies | missing CSP / XFO / HSTS / XCTO / Referrer-Policy / Permissions-Policy, cookie `HttpOnly/Secure/SameSite` audit, server version disclosure |
| Exposed paths | conventional sensitive paths (`.env`, `.git/HEAD`, backups) with content-aware leak confirmation |
| WAF/CDN fingerprint | passive header + benign-payload response analysis (Cloudflare, AWS WAF, Akamai, mod_security, Imperva, …) — informational, changes your encoding strategy |

Every finding carries the exact vector URLs used, so you can reproduce or extend it by hand. Reports land as **JSON + Markdown + SARIF 2.1.0** — pipe the SARIF straight into GitHub Security tab, VS Code, or DefectDojo.

## The scope gate

**awscan refuses to send a single request to a host that is not listed in your scope file.** This is a hard gate, not a flag — it also re-checks inside the crawler before every hop:

```
$ python3 -m awscan.cli --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file — refusing to send any request.
```

Add hosts only when you hold written/program authorization: your own assets, a lab, or a bug-bounty program's declared scope.

## Quick start

```bash
git clone https://github.com/0xgetz/awscan && cd awscan
cp scope.example.txt my-scope.txt        # edit: add your authorized hosts

# 1) self-test against the bundled deliberately-vulnerable lab (loopback only)
python3 lab_server.py --port 8777 &
python3 -m awscan.cli --crawl --root http://127.0.0.1:8777 \
  --scope my-scope.txt --delay 0.05
# → 10 findings incl. blind-extracted secret, bypassed /admin, JS-key sweep

# 2) manual single surface, with your session and blind extraction demo
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) authorized production target (respect the defaults: delay >= 1s)
python3 -m awscan.cli --crawl --root https://in-scope.example.com \
  --scope my-scope.txt --header "Cookie: session=<yours>"
```

`TEST` in a manual target URL is the injection placeholder — the scanner swaps it per payload. With `--crawl` you don't need one.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--target` | — | URL with `TEST` placeholder param value (manual surface) |
| `--crawl` | off | same-origin crawl to discover injectable surfaces automatically |
| `--root` | from target | crawl seed URL |
| `--max-pages` | 60 | crawl page ceiling |
| `--scope` | `scope.example.txt` | authorized hosts file (`*.domain` = subdomain wildcard) |
| `--delay` | `1.0` | seconds between requests (keep ≥ 1 for production) |
| `--budget` | `900` | wall-clock seconds before SIGALRM hard exit — pacing sleeps can't outrun a cooperative deadline check when a socket hangs; this backstop flushes and exits |
| `--header` | none | repeatable auth/custom header, e.g. `--header "Cookie: sid=abc"` (hunt authenticated surfaces) |
| `--extract-sql` | off | demo boolean-blind extraction of one `SELECT` expression |
| `--out` | `reports` | report output directory (JSON + MD + SARIF) |

## Confidence model (the anti-self-fool rule)

A raw byte delta is never a finding. Injection claims require a DBMS error marker **or** a TRUE/FALSE differential on a stable state anchor (row counts). A payload that gets past a WAF without moving the anchor is *not vulnerable* — the tool says so instead of drowning you in raw-scanner noise. Timing findings are always marked `manual verification required` because jitter fakes them. This mirrors the validation discipline bug-bounty programs demand.

## Development

```bash
python3 -m unittest discover -s test   # 27 tests, fully offline (spawns the loopback lab on ephemeral ports)
```

The rules that keep this tool trustworthy are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

- Authorized targets only — the scope gate makes the honest path the easy path.
- Findings are *candidates*; validate manually before reporting or fixing.
- The bundled `lab_server.py` is deliberately insecure and loopback-only. Never expose it.

## License

MIT — see [LICENSE](LICENSE).
