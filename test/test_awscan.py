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
            j, m = report.write_reports(rep, d)
            self.assertTrue(os.path.exists(j) and os.path.exists(m))
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
                self.assertEqual(len(files), 2)
                jpath = next(os.path.join(rdir, f) for f in files if f.endswith(".json"))
                j = json.load(open(jpath))
                names += [f["check"] for f in j["findings"]]
                if sub == "r1":
                    blind = next(f for f in j["findings"] if "blind" in f["check"].lower())
                    self.assertEqual(blind["extracted"], "demo-flag-xk41-7f")
            for want in ("SQL injection", "Reflected XSS", "Open redirect", "Exposed paths"):
                self.assertIn(want, names)

    def test_missing_placeholder_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "scope.txt")
            open(good, "w").write("127.0.0.1\n")
            with self.assertRaises(SystemExit) as cm:
                main(["--target", self.base + "/search?q=nope", "--scope", good, "--out", d + "/r"])
            self.assertIn("placeholder", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
