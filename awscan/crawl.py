"""Same-origin crawler: discovers injectable surfaces without being told them.

Bug hunters in 2026 don't hand-feed parameter URLs anymore — the tool crawls
the authorized app, collects every page + every GET parameter it sees, and
hands each one to the checks. Safety rules baked into this module:

- only same-host http(s) links are followed (no offsite wandering)
- the scope gate is re-checked per URL before any request leaves the process
- polite caps: max_pages, per-path parameter sampling, no POST crawling
"""
import re
import urllib.parse
from collections import deque

from .scope import in_scope

_LINK_HREF = re.compile(r"""<a[^>]+href=["']([^"'#]+)["']""", re.I)
_FORM_ACTION = re.compile(r"""<form[^>]+action=["']([^"'#]+)["']""", re.I)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
MAX_URL_LEN = 2000


def _abs(base_url, href):
    """Resolve href against the *current page* URL — handles both '/abs' and
    '?page=2' relative-to-query links."""
    href = href.strip()
    if href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    return urllib.parse.urljoin(base_url, href)


def discover_injectables(url):
    """[(base_with_TEST, param_name)] for every parameter of *url*; the LAST
    parameter gets the placeholder so _inject swaps exactly one value."""
    u = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    out = []
    for i, (k, _v) in enumerate(pairs):
        swapped = [(name, "TEST" if j == i else val) for j, (name, val) in enumerate(pairs)]
        base = u._replace(query=urllib.parse.urlencode(swapped)).geturl()
        out.append((base, k))
    return out


def crawl(root, sess, hosts, max_pages=60, seed=None):
    """BFS from *seed* (default: site root) over same-origin links.

    Returns (pages, injectable_bases, forbidden_urls).

    pages: set of absolute URLs fetched (includes JS bundle URLs found in
    <script src> — fed to the secret sweep). injectable_bases: unique
    placeholder-URLs ready for checks. forbidden_urls: crawled paths that
    answered 401/403 — fed to the bypass battery. Off-scope links are skipped
    silently; requests only ever go in-scope.
    """
    seed = seed or root + "/"
    seen, queued, fetched, inject, forbidden = set(), set(), set(), {}, []
    queue = deque([seed])
    queued.add(urllib.parse.urlparse(seed)._replace(query="", fragment="").geturl())
    while queue and len(fetched) < max_pages:
        url = queue.popleft()
        if url in seen or len(url) > MAX_URL_LEN:
            continue
        seen.add(url)
        if not in_scope(url, hosts):  # belt-and-braces: never request off-scope
            continue
        r = sess.fetch(url)
        if r.status in (401, 403):
            forbidden.append(url)
            continue
        if r.status < 0:
            continue
        fetched.add(url)
        if r.status in (301, 302, 303, 307, 308):
            loc = r.headers.get("location")
            if loc:
                nxt = _abs(url, loc)
                if nxt:
                    queue.append(nxt)
            continue
        body = r.body or ""
        origin = urllib.parse.urlparse(url).netloc
        groups = []
        for rx in (_LINK_HREF, _FORM_ACTION, _SCRIPT_SRC):
            groups += [m.group(1) for m in rx.finditer(body)]
        for href in groups:
            absu = _abs(url, href)
            if not absu:
                continue
            au = urllib.parse.urlparse(absu)
            if au.scheme not in ("http", "https") or au.netloc != origin:
                continue
            # sample: crawl the clean path once, but register EVERY parameter
            # combination for injection (params are the surface, not pages)
            clean = au._replace(query="", fragment="").geturl()
            for base, name in discover_injectables(absu):
                inject.setdefault(base, name)
            if clean not in queued and len(clean) <= MAX_URL_LEN:
                queued.add(clean)
                queue.append(clean)
    # the seed page itself carries params too
    for base, name in discover_injectables(seed):
        inject.setdefault(base, name)
    return fetched, list(inject.keys()), forbidden
