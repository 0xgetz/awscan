#!/usr/bin/env python3
"""Deliberately-vulnerable LAB server for awscan self-tests. Bind 127.0.0.1 ONLY.

This file demonstrates insecure patterns (SQL string concatenation, raw HTML
reflection, unvalidated redirects). Do not deploy it. Run it only on loopback:

    python3 lab_server.py --port 8777
"""
import argparse
import sqlite3
import socketserver
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler


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

    def _send(self, status, ctype, body):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/search" and "q" in q:
            val = q["q"][0]
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
        elif u.path == "/go":
            # INSECURE BY DESIGN: unvalidated redirect target
            self.send_response(302)
            self.send_header("Location", q.get("to", ["/"])[0])
            self.end_headers()
        elif u.path == "/.env":
            self._send(200, "text/plain", "DATABASE_URL=sqlite:///app.db\n")
        else:
            self._send(200, "text/html", "<h1>awscan lab</h1>")


def serve(port=0):
    """Start the lab in a daemon thread; returns (server, base_url)."""
    global _schema
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
