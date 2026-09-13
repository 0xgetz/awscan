"""Scope loading and enforcement (hard gate)."""
import urllib.parse


def load_scope(path):
    """Read one host per line; ``*.`` prefix = subdomain wildcard. Fails loud on empty."""
    hosts = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip().lower()
                if entry:
                    hosts.add(entry)
    except OSError as exc:
        raise SystemExit(f"[!] cannot read scope file: {exc}") from exc
    if not hosts:
        raise SystemExit("[!] scope file is empty — add one authorized host per line")
    return frozenset(hosts)


def host_of(url):
    return (urllib.parse.urlparse(url).hostname or "").lower()


def in_scope(url, hosts):
    host = host_of(url)
    if not host:
        return False
    for entry in hosts:
        if entry.startswith("*."):
            if host == entry[2:] or host.endswith("." + entry[2:]):
                return True
        elif host == entry:
            return True
    return False


def require_scope(url, hosts):
    """Raise SystemExit unless *url* is authorized. Never let this be bypassed by callers."""
    if not in_scope(url, hosts):
        raise SystemExit(
            f"[!] host '{host_of(url)}' is NOT in the scope file — refusing to send any request. "
            "Add it only if you hold written authorization (bug-bounty scope / lab / your own asset)."
        )
