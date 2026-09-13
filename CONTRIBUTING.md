# Contributing to awscan

Thanks for taking the tool seriously. A few rules keep awscan trustworthy —
they exist because of real-world scanner failures, not taste.

## Non-negotiables

1. **The scope gate stays hard.** No CLI flag, env var, or code path may send
   an active probe to a host that is not in the scope file. PRs that soften it
   (e.g. a `--force`) will be rejected on sight.
2. **No false-confidence detections.** A finding must be backed by a proven
   signal: DBMS error marker, TRUE/FALSE state-anchor differential, or
   byte-identical reflection. Raw response-length deltas are never a finding.
3. **Zero runtime dependencies.** Stdlib only, Python ≥ 3.9. If you think you
   need a package, the check is wrong or belongs in another tool.
4. **Pacing by default.** `--delay` must default ≥ 1s; new checks must respect
   the session rate limiter. DoS-style parallel scanning is out of scope.
5. **Every detection ships with a lab proof.** Add or extend a route in
   `lab_server.py` (loopback only) and a positive + negative test pair. A
   check without a negative test can self-fool exactly like the false
   positives this tool exists to avoid.

## Setup

```bash
git clone https://github.com/0xgetz/awscan && cd awscan
python3 -m unittest discover -s test    # must be green before you touch anything
```

Tests run fully offline: each case spins `lab_server.py` on an ephemeral
127.0.0.1 port. Never point tests or scripts at external hosts. The crawler
re-checks scope on every hop — keep it that way.

## Adding a check

1. New function in `awscan/checks.py` returning `dict | None`, following the
   existing shape (`check`, `confidence[]`, `vectors{}`).
2. Positive + negative unit tests in `test/test_awscan.py`, plus the lab
   route that demonstrates it.
3. Wire it into `awscan/cli.py` under `note(...)`.
4. Update README (all three languages: `README.md`, `README.id.md`,
   `README.zh-CN.md`) — headers and tables must stay parallel — and
   `CHANGELOG.md`.

## Style

- `snake_case`, intent-named constants at module top (payload lists, regexes).
- Comments only for non-obvious mechanics (why `-- ` suffix, why lowercase headers).
- Fail loud early: bad scope/config aborts with a one-line reason, no traceback.

## Reporting a bug

Include: the exact `--target` (redact the host if it isn't public scope),
`--delay/--budget`, Python version, and the JSON report. Detections are
evidence-bearing — attach the vector URLs so we can reproduce without you
re-scanning.
