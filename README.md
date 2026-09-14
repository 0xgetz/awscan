<div align="center">
  <img src="assets/logo.png" alt="awscan logo" width="128" height="128">
  <h1>awscan</h1>
  <p>Automated web vulnerability scanner for authorized security testing.<br>
  Zero dependencies. Python 3.9+, standard library only.</p>
  <p>
    <a href="https://github.com/0xgetz/awscan/releases"><img src="https://img.shields.io/github/v/release/0xgetz/awscan?color=e8a33d" alt="release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license"></a>
    <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
    <img src="https://img.shields.io/badge/deps-none-informational" alt="zero dependencies">
  </p>
  <p>
    English · <a href="README.id.md">Bahasa Indonesia</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a>
  </p>
</div>

## What it is

awscan gives a target site a battery of proven injection, information-disclosure, and misconfiguration checks, then reports every finding with the exact request vectors so you can reproduce it by hand. It is built around two disciplines most tooling skips:

1. **A hard scope gate.** The scanner refuses to send a single request to any host that is not in your scope file. No flag bypasses it; the crawler re-checks the gate before every hop.
2. **A confidence model.** A raw byte-length delta is never a finding. Injection claims require a DBMS error marker or a TRUE/FALSE differential on a stable anchor. Timing results are always flagged for manual recheck because jitter fakes them.

Reports land as JSON, Markdown, and SARIF 2.1.0. The SARIF file imports directly into the GitHub Security tab, VS Code, or DefectDojo, and each result carries its CWE mapping.

## Checks

| Area | Technique |
|---|---|
| Same-origin crawl | BFS over links, forms, and JS bundles to discover pages and every GET parameter; 401/403 paths are collected for the bypass battery |
| SQL injection | DBMS error-marker sniff plus a TRUE/FALSE differential oracle on stable state anchors |
| Boolean-blind extraction | Character-by-character recovery through the confirmed oracle, portable `substr()` equality (SQLite, MySQL, PostgreSQL shapes) |
| Time-based blind SQLi | Stacked-delay payloads (MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR`) measured against median baseline latency |
| Reflected XSS | Byte-identical reflection of a unique probe with an unencoded quote, then an event-handler confirmation |
| SSTI | Arithmetic template probes (`{{7*7}}` class, `${...}`, ERB, Freemarker); a hit requires the probe to come back computed, not echoed |
| Open redirect | Parameter swap to an external canary host, verified on the `Location` header |
| Host header injection | Canary `Host:` header reflected in body or links; the password-reset poisoning class |
| 403/401 bypass | Path tricks (`;/`, `..;`, `%2e`, double-slash) plus header tricks (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) against every forbidden path found |
| GraphQL | Read-only `__schema` introspection probe on common endpoints |
| Secrets in JS | Sweep of crawled bundles for AWS, GCP, GitHub, Stripe, JWT, and private-key patterns; values are masked in reports, never written in full |
| Headers & cookies | Missing CSP, X-Frame-Options, HSTS, XCTO, Referrer-Policy, Permissions-Policy; cookie HttpOnly/Secure/SameSite audit; server version disclosure |
| Exposed paths | Conventional sensitive paths (`.env`, `.git/HEAD`, backups) with content-aware confirmation |
| WAF/CDN fingerprint | Passive header and benign-payload response analysis (Cloudflare, AWS WAF, Akamai, mod_security, Imperva); informational, tells you which encoding strategy to switch to |

## Requirements

- Python 3.9 or newer, no third-party packages
- Written authorization for every target you point it at

## Install

```bash
# from GitHub (pipx, uv, or pip all work)
pipx install git+https://github.com/0xgetz/awscan.git
# or run straight from a clone, no install step
git clone https://github.com/0xgetz/awscan && cd awscan
python3 -m awscan.cli --help
```

## The scope gate

```
$ awscan --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file. Refusing to send any request.
```

Add hosts only when you hold authorization: a bug-bounty program's declared scope, your own assets, or a lab. The example file ships pre-filled with loopback entries only.

## Quick start

```bash
cp scope.example.txt my-scope.txt   # edit: add your authorized hosts

# 1) Self-test against the bundled deliberately-vulnerable lab (loopback only)
python3 lab_server.py --port 8777 &
awscan --crawl --root http://127.0.0.1:8777 --scope my-scope.txt --delay 0.05
# → 10 findings on the lab: SQLi (incl. blind-extracted secret), SSTI, XSS,
#   open redirect, host-header injection, bypassed /admin, GraphQL, JS secrets,
#   exposed paths, header hygiene

# 2) Manual single surface with authenticated session and blind extraction demo
awscan --target "http://127.0.0.1:8777/search?q=TEST" --scope my-scope.txt \
  --delay 0.05 --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) Authorized production target (keep the polite defaults: delay >= 1s)
awscan --crawl --root https://in-scope.example.com --scope my-scope.txt \
  --header "Cookie: session=<yours>"
```

In a manual `--target` URL, `TEST` is the injection placeholder the scanner swaps per payload. With `--crawl` you never need one.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `--target` | (required unless crawling) | URL with a `TEST` placeholder param value |
| `--crawl` | off | Same-origin crawl that discovers injectable surfaces automatically |
| `--root` | from target | Crawl seed URL |
| `--max-pages` | 60 | Crawl page ceiling |
| `--scope` | `scope.example.txt` | Authorized hosts file; `*.domain` matches subdomains |
| `--delay` | 1.0 | Seconds between requests (keep >= 1 on production) |
| `--budget` | 900 | Wall-clock seconds before a hard exit; the backstop a hung socket cannot outrun |
| `--header` | none | Repeatable custom header, e.g. `--header "Cookie: sid=abc"` |
| `--extract-sql` | off | Boolean-blind demo extraction of one SELECT expression |
| `--out` | `reports` | Output directory for JSON, Markdown, and SARIF |

## Development

```bash
python3 -m unittest discover -s test   # 27 tests, fully offline
```

The suite spawns the loopback lab on ephemeral ports for every case; nothing touches the network. The rules that keep this tool trustworthy are written down in [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

- Authorized targets only. The scope gate exists to make the honest path the easy path.
- Findings are candidates. Validate each one manually before reporting or fixing.
- `lab_server.py` is deliberately insecure and loopback-only. Never expose it.

## License

MIT. See [LICENSE](LICENSE).
