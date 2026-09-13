# Changelog

All notable changes to **awscan** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
semantic versioning.

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
