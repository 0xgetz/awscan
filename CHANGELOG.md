# Changelog

All notable changes to **awscan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
semantic versioning.

## [1.1.0] - 2026-09-13

The 2026 bug-hunter technique release.

### Added
- Same-origin **crawler** (`--crawl --root URL`): BFS discovery of pages and
  every GET parameter — no more hand-fed placeholder URLs. Forbidden
  (401/403) paths discovered during the crawl feed the bypass battery.
- **SSTI** detection via arithmetic template probes (Jinja/Twig `${{…}}`, ERB,
  Freemarker): a finding requires the probe to come back *computed*, never echoed.
- **Host header injection** canary check — the password-reset-poisoning class.
- **403/401 bypass battery**: path tricks (`;/`, `..;`, `%2e`, double-slash)
  and header tricks (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`).
- **Time-based blind SQLi** with stacked-delay payloads vs. median baseline
  latency; always flagged `manual_verify` because jitter fakes timing.
- **GraphQL introspection** probe (read-only `__schema`) on common endpoints.
- **JS bundle secret sweep** (AWS/GCP/GitHub/Stripe/JWT/private-key) with
  values MASKED in reports — full secrets never hit disk.
- **WAF/CDN fingerprint** (Cloudflare, AWS WAF, Akamai, mod_security,
  Imperva, Wallarm, Fastly) — passive + benign-payload response analysis.
- Cookie attribute audit (`HttpOnly`/`Secure`/`SameSite`) inside exposed-path findings.
- `--header "Name: value"` (repeatable) so authenticated surfaces can be tested.
- **SARIF 2.1.0** report output alongside JSON + Markdown — ingestable by the
  GitHub Security tab, VS Code, and DefectDojo, with per-check CWE mapping.
- Response body cap (512 KB) — a scanner must never OOM on a giant page.
- Lab expanded: SSTI, stacked-delay emulation, Host trust, IP-allowlist
  "auth", permissive GraphQL, secret-bearing JS bundle, flagless cookies.
- Test suite: 17 → **27 tests**, all offline, every new check ships with a
  positive test and a negative test where meaningful.

## [1.0.0] - 2026-09-13

First public release.

### Added
- Hard scope gate: refuses any active request to a host outside the scope
  file (exact host + `*.domain` subdomain wildcard).
- SQL injection detection: DBMS error-marker sniff (SQLite/MySQL/PostgreSQL/
  Oracle/MSSQL) combined with a TRUE/FALSE state-anchor differential.
- Boolean-blind extraction over the confirmed oracle using portable
  `substr()` equality (works without vendor-specific `ascii()`).
- Reflected XSS: unique-token byte-identical reflection probe plus an
  event-handler payload confirmation.
- Open redirect via redirect-parameter swap to an external canary host,
  verified on the `Location` response header.
- Security-header audit (CSP / X-Frame-Options / HSTS / X-Content-Type-Options)
  plus server version disclosure.
- Common sensitive path probing with content-aware leak confirmation
  (`.env`, `.git/HEAD`, backups).
- Cooperative rate limiter (`--delay`, default 1s) backed by a SIGALRM
  wall-clock budget (`--budget`) so a hung socket can't outrun the deadline.
- JSON + Markdown reports carrying exact vector URLs per finding.
- Bundled deliberately-vulnerable lab (`lab_server.py`, loopback-only) used
  by the fully-offline 17-test suite.
- README in English, Bahasa Indonesia, and 简体中文; MIT license;
  CONTRIBUTING with the detection-evidence bar.
