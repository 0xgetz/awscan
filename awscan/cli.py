"""CLI: awscan --target URL --scope scope.txt [options]."""
import argparse
import os
import signal
import sys
import time
import urllib.parse

from . import __version__
from .checks import blind_extract, check_headers, check_open_redirect, check_paths, check_sqli, check_xss
from .net import Session
from .report import build_report, write_reports
from .scope import load_scope, require_scope

PLACEHOLDER = "TEST"


def budget_alarm(seconds):
    """SIGALRM backstop — cooperative pacing can hang inside one long request."""
    def _fire(_sig, _frm):
        sys.stdout.flush()
        print("[!] wall-clock budget exceeded — flushing report and exiting")
        os._exit(3)
    try:
        signal.signal(signal.SIGALRM, _fire)
        signal.alarm(seconds)
    except (AttributeError, ValueError):
        pass  # non-POSIX or nested: cooperative timing only


def run(args):
    hosts = load_scope(args.scope)
    require_scope(args.target, hosts)
    if PLACEHOLDER not in urllib.parse.urlparse(args.target).query:
        raise SystemExit(f"[!] --target must embed placeholder '{PLACEHOLDER}' as the injected param value")
    u = urllib.parse.urlparse(args.target)
    root = f"{u.scheme}://{u.netloc}"
    sess = Session(delay=args.delay)
    sess.t0 = time.time()
    budget_alarm(args.budget)

    findings = []

    def note(label, result):
        print(f"[*] {label}: {'HIT' if result else 'clean'}")
        if result:
            findings.append(result)
        return result

    note("sql-injection (error+differential)", check_sqli(args.target, sess))
    xss = note("reflected-xss", check_xss(args.target, sess, "aw" + os.urandom(4).hex()))
    note("open-redirect", check_open_redirect(root, sess))
    note("security-headers", check_headers(root, sess))
    note("common-paths", check_paths(root, sess))
    if args.extract_sql:
        val = blind_extract(args.target, sess, args.extract_sql)
        if val:
            findings.append({"check": "Boolean-blind SQL extraction",
                             "confidence": [f"extracted {len(val)} chars via the confirmed oracle"],
                             "extracted": val, "vectors": {"expression": args.extract_sql}}
                            )
        print(f"[*] blind-extract: {'extracted ' + repr(val) if val else 'no working oracle'}")
    if hasattr(signal, "alarm"):
        signal.alarm(0)
    return build_report(args.target, args.scope, findings, time.time() - sess.t0, sess.requests)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="awscan", description="Automated web vulnerability scanner for AUTHORIZED targets only.")
    ap.add_argument("--version", action="version", version=f"awscan {__version__}")
    ap.add_argument("--target", required=True, help=f"URL with {PLACEHOLDER} param placeholder, e.g. http://127.0.0.1:8777/search?q={PLACEHOLDER}")
    ap.add_argument("--scope", default=os.path.join(os.path.dirname(__file__), "..", "scope.example.txt"))
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests (>=1 for production)")
    ap.add_argument("--budget", type=int, default=900, help="wall-clock seconds before hard exit")
    ap.add_argument("--extract-sql", default=None, help="demo boolean-blind extraction of one SELECT expression")
    ap.add_argument("--out", default="reports", help="report output directory")
    args = ap.parse_args(argv)
    t0 = time.time()
    rep = run(args)
    rep["duration_s"] = round(time.time() - t0, 1)
    j, m = write_reports(rep, args.out)
    print(f"[+] {len(rep['findings'])} finding(s) · {rep['requests']} requests\n    {j}\n    {m}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
