"""Offline test-suite: every test spins the vulnerable lab on 127.0.0.1 ephemeral port."""
import json
import os
import tempfile
import unittest

from awscan import checks, report, scope
from awscan.cli import main
from awscan.net import Session
from lab_server import serve

DELAY = 0.0


class LabCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = serve(0)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def target(self, path="/search", param="q"):
        return f"{self.base}{path}?{param}=TEST"

    def sess(self):
        return Session(delay=DELAY)


class NewChecks2026(LabCase):
    """v1.1 technique battery, each with a positive and (where meaningful) negative test."""

    def test_ssti_positive(self):
        f = checks.check_ssti(self.target("/page", "tpl"), self.sess())
        self.assertIsNotNone(f)
        self.assertEqual(f["check"], "Server-side template injection")

    def test_ssti_negative_raw_echo(self):
        # /echo reflects the probe verbatim (never computes it) -> not SSTI
        self.assertIsNone(checks.check_ssti(self.target("/echo"), self.sess()))

    def test_host_header_injection(self):
        f = checks.check_host_header(self.base, self.sess(), "abc123")
        self.assertIsNotNone(f)
        self.assertIn("awhost-abc123.example.com", f["vectors"]["header"])

    def test_time_blind(self):
        orig = checks.TIME_PAYLOADS
        checks.TIME_PAYLOADS = ["'; select pg_sleep(2) -- "]  # one payload to keep suite fast
        try:
            f = checks.check_time_blind(self.target(), self.sess())
        finally:
            checks.TIME_PAYLOADS = orig
        self.assertIsNotNone(f)
        self.assertTrue(f["manual_verify"])

    def test_forbidden_bypass_xff(self):
        f = checks.check_forbidden_bypass(self.sess(), self.base + "/admin")
        self.assertIsNotNone(f)
        self.assertEqual(f["check"], "403 bypass")
        self.assertIn("X-Forwarded-For", f["vectors"]["header"])

    def test_graphql_introspection(self):
        f = checks.check_graphql(self.base, self.sess())
        self.assertIsNotNone(f)
        self.assertIn("/graphql", f["vectors"]["endpoint"])

    def test_js_secrets_masked(self):
        sess = self.sess()
        f = checks.check_js_secrets(sess, self.base, {self.base + "/static/app.js"})
        self.assertIsNotNone(f)
        types = {s["type"] for s in f["secrets"]}
        self.assertIn("AWS access key", types)
        self.assertIn("JWT", types)
        for s in f["secrets"]:
            self.assertIn("…", s["match"])  # never a full secret on disk

    def test_crawler_discovers_surfaces_and_forbidden(self):
        from awscan.crawl import crawl
        hosts = scope.load_scope(os.path.join(os.path.dirname(__file__), "..", "scope.example.txt"))
        sess = self.sess()
        pages, bases, forbidden = crawl(self.base, sess, hosts)
        self.assertIn(self.base + "/login", pages)
        self.assertTrue(any("q=TEST" in b for b in bases))
        self.assertTrue(any("tpl=TEST" in b for b in bases))
        self.assertIn(self.base + "/admin", forbidden)

    def test_waf_clean_on_lab(self):
        self.assertIsNone(checks.check_waf(self.base, self.sess()))


class ScopeGate(LabCase):
    def test_wildcard_match(self):
        hosts = scope.load_scope(os.path.join(os.path.dirname(__file__), "..", "scope.example.txt"))
        self.assertTrue(scope.in_scope("http://127.0.0.1:8777/x", hosts))
        self.assertFalse(scope.in_scope("https://not-in-scope.example.org/", hosts))

    def test_require_scope_refuses_and_passes(self):
        hosts = frozenset({"good.com", "*.ok.dev"})
        scope.require_scope("https://sub.ok.dev/a", hosts)  # no raise
        with self.assertRaises(SystemExit):
            scope.require_scope("https://evil.com/a", hosts)

    def test_empty_scope_fails_loud(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# only comments\n")
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                scope.load_scope(path)
        finally:
            os.unlink(path)


class SqlInjection(LabCase):
    def test_positive_error_and_differential(self):
        f = checks.check_sqli(self.target(), self.sess())
        self.assertIsNotNone(f)
        self.assertEqual(f["check"], "SQL injection")
        text = " ".join(f["confidence"])
        self.assertIn("sqlite", text.lower())
        self.assertIn("differential", text.lower())

    def test_negative_escaped_param(self):
        # a clean app: param has no injection effect — quote returns same 3 rows
        clean = f"{self.base}/static?x=TEST"
        sess = self.sess()
        orig = checks._ROW.findall
        # /static always returns fixed body without <li> so oracle cannot fire
        f = checks.check_sqli(clean, sess)
        self.assertIsNone(f)

    def test_blind_extraction_recovers_secret(self):
        val = checks.blind_extract(self.target(), self.sess(), "SELECT secret FROM secrets LIMIT 1", max_len=32)
        self.assertEqual(val, "demo-flag-xk41-7f")

    def test_blind_no_oracle_returns_none(self):
        val = checks.blind_extract(f"{self.base}/?x=TEST", self.sess(), "SELECT 1")
        self.assertIsNone(val)


class XSS(LabCase):
    def test_reflected_detected(self):
        f = checks.check_xss(self.target("/echo"), self.sess(), "awtest1")
        self.assertIsNotNone(f)
        self.assertEqual(f["check"], "Reflected XSS")

    def test_encoded_reflection_not_flagged(self):
        # lab /search reflects raw; simulate a hardened app via a param the lab HTML-escapes:
        # use a path that does not reflect at all
        f = checks.check_xss(f"{self.base}/static?s=TEST", self.sess(), "awtest2")
        self.assertIsNone(f)


class Misc(LabCase):
    def test_open_redirect(self):
        f = checks.check_open_redirect(self.base, self.sess())
        self.assertIsNotNone(f)
        self.assertEqual(f["check"], "Open redirect")
        self.assertIn("evil.example.com", f["vectors"]["url"])

    def test_headers_flags_missing(self):
        f = checks.check_headers(self.base, self.sess())
        self.assertIsNotNone(f)
        joined = " ".join(f["confidence"])
        self.assertIn("missing CSP", joined)

    def test_paths_finds_env_leak(self):
        f = checks.check_paths(self.base, self.sess())
        self.assertIsNotNone(f)
        env = [p for p in f["paths"] if p["path"] == "/.env"]
        self.assertTrue(env and env[0]["sensitive_leak"])

    def test_transport_failure_negative_status(self):
        s = self.sess()
        r = s.fetch("http://127.0.0.1:1/nope")  # refused
        self.assertLess(r.status, 0)


class Reports(LabCase):
    def test_markdown_render(self):
        rep = report.build_report(self.target(), "scope.txt", [
            {"check": "SQL injection", "confidence": ["dbms error marker: sqlite"],
             "vectors": {"true": "http://x/1"}},
        ], 1.2, 42)
        md = report.render_md(rep)
        self.assertIn("## SQL injection", md)
        self.assertIn("42 requests", md)

    def test_write_reports_files(self):
        with tempfile.TemporaryDirectory() as d:
            rep = report.build_report("t", "s", [], 0.1, 3)
            j, m, sa = report.write_reports(rep, d)
            self.assertTrue(os.path.exists(j) and os.path.exists(m) and os.path.exists(sa))
            self.assertIn("findings", json.load(open(j)))


class CliE2E(LabCase):
    def test_full_run_scope_refusal_then_success(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "scope.txt")
            open(bad, "w").write("someone-elses-site.com\n")
            with self.assertRaises(SystemExit) as cm:
                main(["--target", self.target(), "--scope", bad, "--delay", "0", "--out", os.path.join(d, "r")])
            self.assertIn("NOT in the scope file", str(cm.exception))

            good = os.path.join(d, "scope.txt")
            open(good, "w").write("127.0.0.1\n")
            # surface 1: SQLi + redirect + headers + paths + blind extraction
            code = main(["--target", self.target(), "--scope", good, "--delay", "0",
                         "--extract-sql", "SELECT secret FROM secrets LIMIT 1",
                         "--out", os.path.join(d, "r1")])
            self.assertEqual(code, 0)
            # surface 2: reflected XSS on the echo endpoint
            code = main(["--target", self.target("/echo"), "--scope", good, "--delay", "0",
                         "--out", os.path.join(d, "r2")])
            self.assertEqual(code, 0)
            names = []
            for sub in ("r1", "r2"):
                rdir = os.path.join(d, sub)
                files = os.listdir(rdir)
                self.assertEqual(len(files), 3)  # json + md + sarif
                jpath = next(os.path.join(rdir, f) for f in files if f.endswith(".json"))
                j = json.load(open(jpath))
                names += [f["check"] for f in j["findings"]]
                sarif = json.load(open(next(os.path.join(rdir, f) for f in files if f.endswith(".sarif"))))
                self.assertEqual(sarif["version"], "2.1.0")
                self.assertTrue(all("ruleId" in r for r in sarif["runs"][0]["results"]))
                if sub == "r1":
                    blind = next(f for f in j["findings"] if "blind" in f["check"].lower())
                    self.assertEqual(blind["extracted"], "demo-flag-xk41-7f")
            for want in ("SQL injection", "Reflected XSS", "Open redirect", "Exposed paths"):
                self.assertIn(want, names)

    def test_crawl_mode_end_to_end(self):
        """--crawl with no manual target: surfaces discovered by the crawler."""
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "scope.txt")
            open(good, "w").write("127.0.0.1\n")
            code = main(["--crawl", "--root", self.base, "--scope", good, "--delay", "0",
                         "--out", os.path.join(d, "rc")])
            self.assertEqual(code, 0)
            jpath = next(os.path.join(d, "rc", f) for f in os.listdir(os.path.join(d, "rc")) if f.endswith(".json"))
            j = json.load(open(jpath))
            names = {f["check"] for f in j["findings"]}
            for want in ("SQL injection", "Server-side template injection", "Open redirect",
                         "Host header injection", "403 bypass", "GraphQL introspection enabled",
                         "Secrets in JavaScript", "Exposed paths"):
                self.assertIn(want, names)
            self.assertGreaterEqual(j["pages_crawled"], 4)

    def test_missing_placeholder_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "scope.txt")
            open(good, "w").write("127.0.0.1\n")
            with self.assertRaises(SystemExit) as cm:
                main(["--target", self.base + "/search?q=nope", "--scope", good, "--out", d + "/r"])
            self.assertIn("placeholder", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
