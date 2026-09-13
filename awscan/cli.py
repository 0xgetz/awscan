"""CLI: awscan --target URL --scope scope.txt [options]."""
import argparse
import json
import os
import signal
import sys
import time
import urllib.parse

from . import __version__
from .checks import (blind_extract, check_forbidden_bypass, check_graphql, check_headers,
                     check_host_header, check_js_secrets, check_open_redirect, check_paths,
                     check_sqli, check_ssti, check_time_blind, check_waf, check_xss)
from .crawl import crawl
from .net import Session
from .report import build_report, write_reports
from .scope import load_scope, require_scope

PLACEHOLDER = "TEST"
MAX_INJECT_SURFACES = 20  # ceiling: a crawl can surface hundreds of param combos


def budget_alarm(seconds):
    """SIGALRM backstop — cooperative pacing can hang inside one long request."""
    def _fire(_sig, _frm):
        sys.stdout.flush()
        print("[!] wall-clock budget exceeded — partial report may be lost; rerun with a bigger --budget")
        os._exit(3)
    try:
        signal.signal(signal.SIGALRM, _fire)
        signal.alarm(seconds)
    except (AttributeError, ValueError):
        pass  # non-POSIX or nested: cooperative timing only


def parse_auth_headers(pairs):
    """--header 'Cookie: sid=...' repeatable; refuse malformed loudly."""
    out = {}
    for p in pairs or []:
        if ":" not in p:
            raise SystemExit(f"[!] --header expects 'Name: value', got: {p!r}")
        k, v = p.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def surfaces_for(args, sess, hosts, root):
    """The parameter surfaces to attack: crawl-discovered or the manual target."""
    if args.crawl:
        pages, bases, forbidden = crawl(root, sess, hosts, max_pages=args.max_pages,
                                        seed=args.target or None)
        print(f"[*] crawler: {len(pages)} pages, {len(bases)} injectable surfaces, {len(forbidden)} forbidden paths")
        return pages, bases[:MAX_INJECT_SURFACES], forbidden
    return set(), [args.target], []


def run(args):
    hosts = load_scope(args.scope)
    require_scope(args.target or args.root, hosts)
    u = urllib.parse.urlparse(args.target or args.root)
    root = f"{u.scheme}://{u.netloc}"
    if not args.crawl and PLACEHOLDER not in urllib.parse.urlparse(args.target).query:
        raise SystemExit(f"[!] --target must embed placeholder '{PLACEHOLDER}' as the injected param "
                         "value, or use --crawl to discover surfaces automatically")
    sess = Session(delay=args.delay, headers=parse_auth_headers(args.header))
    sess.t0 = time.time()
    budget_alarm(args.budget)

    findings = []
    _seen = set()

    def note(label, result):
        if result:
            key = (result["check"], json.dumps(result.get("vectors"), sort_keys=True))
            if key in _seen:
                print(f"[*] {label}: duplicate (already reported)")
                return None
            _seen.add(key)
        print(f"[*] {label}: {'HIT' if result else 'clean'}")
        if result:
            findings.append(result)
        return result

    pages, bases, forbidden = surfaces_for(args, sess, hosts, root)

    for base in bases:
        param = urllib.parse.parse_qsl(urllib.parse.urlparse(base).query)[-1][0] if "?" in base else "-"
        label = f"[{param}] {'/'.join(urllib.parse.urlparse(base).path.split('/'))}" or "/"
        hit = note(f"sqli {label}", check_sqli(base, sess))
        note(f"ssti {label}", check_ssti(base, sess))
        note(f"xss {label}", check_xss(base, sess, "aw" + os.urandom(4).hex()))
        if hit and args.extract_sql:
            val = blind_extract(base, sess, args.extract_sql)
            if val:
                findings.append({"check": "Boolean-blind SQL extraction",
                                 "confidence": [f"extracted {len(val)} chars via the confirmed oracle"],
                                 "extracted": val, "vectors": {"expression": args.extract_sql, "url": base}})
            print(f"[*] blind-extract: {'extracted ' + repr(val) if val else 'no working oracle'}")
        if not hit and args.delay >= 0.05:  # timing is meaningless on a local lab at 0 delay
            note(f"time-blind {label}", check_time_blind(base, sess))
        note(f"redirect {label}", check_open_redirect(root, sess, target=base))

    note("host-header", check_host_header(root, sess, os.urandom(3).hex()))
    note("graphql", check_graphql(root, sess))
    note("waf-fingerprint", check_waf(root, sess))
    note("security-headers", check_headers(root, sess))
    paths_hit = note("common-paths", check_paths(root, sess))
    if paths_hit:
        for p in paths_hit.get("paths", []):
            if p.get("forbidden"):
                note(f"403-bypass {p['path']}", check_forbidden_bypass(sess, root + p["path"]))
    for url in forbidden:
        note(f"403-bypass {urllib.parse.urlparse(url).path}", check_forbidden_bypass(sess, url))
    if args.crawl:
        note("js-secrets", check_js_secrets(sess, root, pages))

    if hasattr(signal, "alarm"):
        signal.alarm(0)
    pages_crawled = len(pages) if args.crawl else 1
    return build_report(args.target or args.root, args.scope, findings,
                        time.time() - sess.t0, sess.requests, pages_crawled)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="awscan", description="Automated web vulnerability scanner for AUTHORIZED targets only.")
    ap.add_argument("--version", action="version", version=f"awscan {__version__}")
    ap.add_argument("--target", default=None, help=f"URL with {PLACEHOLDER} param placeholder (manual surface), e.g. http://127.0.0.1:8777/search?q={PLACEHOLDER}")
    ap.add_argument("--crawl", action="store_true", help="same-origin crawl to discover injectable surfaces automatically")
    ap.add_argument("--root", default=None, help="crawl seed URL (defaults to --target host root)")
    ap.add_argument("--max-pages", type=int, default=60, help="crawl page ceiling (default 60)")
    ap.add_argument("--scope", default=os.path.join(os.path.dirname(__file__), "..", "scope.example.txt"))
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests (>=1 for production)")
    ap.add_argument("--budget", type=int, default=900, help="wall-clock seconds before hard exit")
    ap.add_argument("--header", action="append", metavar="NAME: value",
                    help="auth/custom header, repeatable (e.g. --header 'Cookie: sid=abc')")
    ap.add_argument("--extract-sql", default=None, help="demo boolean-blind extraction of one SELECT expression")
    ap.add_argument("--out", default="reports", help="report output directory")
    args = ap.parse_args(argv)
    if not args.target and not args.crawl:
        raise SystemExit("[!] give --target and/or --crawl")
    if args.crawl and not args.root and not args.target:
        raise SystemExit("[!] --crawl needs --root (site URL to start from)")
    t0 = time.time()
    rep = run(args)
    rep["duration_s"] = round(time.time() - t0, 1)
    j, m, s = write_reports(rep, args.out)
    print(f"[+] {len(rep['findings'])} finding(s) · {rep['requests']} requests\n    {j}\n    {m}\n    {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
