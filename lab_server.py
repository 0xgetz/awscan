#!/usr/bin/env python3
"""Deliberately-vulnerable LAB server for awscan self-tests. Bind 127.0.0.1 ONLY.

Demonstrates insecure patterns: SQL concatenation, raw reflection, unvalidated
redirect, template evaluation, stacked-delay emulation, Host-header trust,
IP-allowlist "auth", leaked JS secrets, permissive GraphQL, flagless cookies.
Do not deploy it. Run it only on loopback:

    python3 lab_server.py --port 8777
"""
import argparse
import json
import re
import socketserver
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler

_TPL = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


def make_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
    conn.executemany("INSERT INTO notes(body) VALUES(?)", [("alpha",), ("bravo",), ("charlie",)])
    conn.execute("CREATE TABLE secrets(id INTEGER PRIMARY KEY, secret TEXT)")
    conn.execute("INSERT INTO secrets(secret) VALUES('demo-flag-xk41-7f')")
    return conn


class LabHandler(BaseHTTPRequestHandler):
    conn = None

    def log_message(self, *args):
        pass

    def _send(self, status, ctype, body, extra=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("content-length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if u.path == "/graphql" and "__schema" in body:
            # INSECURE BY DESIGN: introspection enabled without auth
            self._send(200, "application/json",
                       json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}))
            return
        self._send(404, "text/plain", "not found")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        host = self.headers.get("Host", "")

        if u.path == "/search" and "q" in q:
            val = q["q"][0]
            # INSECURE BY DESIGN: emulate a backend that executes stacked delays
            if re.search(r"sleep\(|waitfor\sdelay|pg_sleep", val, re.I):
                time.sleep(2)
            try:
                # INSECURE BY DESIGN: string concatenation into SQL (lab bug)
                rows = self.conn.execute(
                    "SELECT body FROM notes WHERE body LIKE '%" + val + "%'").fetchall()
            except sqlite3.Error as exc:
                self._send(500, "text/html", f"sqlite3.OperationalError: {exc}")
                return
            listed = "".join(f"<li>{r[0]}</li>" for r in rows)
            self._send(200, "text/html", f"<ul>{listed}</ul>")
        elif u.path == "/echo" and "q" in q:
            # INSECURE BY DESIGN: raw reflection of the param (no SQL involved)
            self._send(200, "text/html", f"<p>you searched: {q['q'][0]}</p>")
        elif u.path == "/page" and "tpl" in q:
            # INSECURE BY DESIGN: template syntax is *evaluated* server-side
            m = _TPL.search(q["tpl"][0])
            out = str(int(m.group(1)) * int(m.group(2))) if m else q["tpl"][0]
            self._send(200, "text/html", f"<div>rendered: {out}</div>")
        elif u.path == "/go":
            self.send_response(302)
            self.send_header("Location", q.get("to", ["/"])[0])
            self.end_headers()
        elif u.path == "/reset":
            # INSECURE BY DESIGN: password-reset page bounces to caller-chosen URL
            self.send_response(302)
            self.send_header("Location", q.get("to", ["/"])[0])
            self.end_headers()
        elif u.path == "/login":
            # INSECURE BY DESIGN: session cookie without HttpOnly/Secure/SameSite
            self._send(200, "text/html", "<h1>login</h1>",
                       extra={"Set-Cookie": "session=abcdef123456; Path=/"})
        elif u.path == "/admin":
            # INSECURE BY DESIGN: "IP allowlist" that trusts a forgeable header
            if self.headers.get("X-Forwarded-For") == "127.0.0.1":
                self._send(200, "text/html", "<h1>admin dashboard</h1>")
            else:
                self._send(403, "text/html", "<h1>403 forbidden</h1>")
        elif u.path == "/static/app.js":
            # INSECURE BY DESIGN: production bundle shipped a hardcoded key
            self._send(200, "application/javascript",
                       'const API = "AKIA1234567890ABCDEF";\n'
                       'const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";\n')
        elif u.path == "/.env":
            self._send(200, "text/plain", "DATABASE_URL=sqlite:///app.db\n")
        elif u.path == "/":
            # INSECURE BY DESIGN: absolute asset URL built from the Host header
            self._send(200, "text/html",
                       f'<h1>awscan lab</h1>'
                       f'<a href="/search?q=alpha">notes</a>'
                       f'<a href="/login">login</a>'
                       f'<a href="/admin">admin</a>'
                       f'<a href="/page?tpl=hello">page</a>'
                       f'<script src="http://{host}/static/app.js"></script>')
        else:
            self._send(404, "text/html", "<h1>not found</h1>")


def serve(port=0):
    """Start the lab in a daemon thread; returns (server, base_url)."""
    handler = type("Bound", (LabHandler,), {"conn": make_db()})
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    actual = srv.server_address[1]
    return srv, f"http://127.0.0.1:{actual}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8777)
    args = ap.parse_args()
    srv, url = serve(args.port)
    print(f"lab listening on {url} (loopback only) — ctrl-c to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
