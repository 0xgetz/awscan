"""HTTP session: rate-limited, redirect-transparent, failure-tolerant."""
import http.client
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.error import HTTPError
from urllib.request import Request, build_opener

MAX_BODY = 512_000  # cap response reads — a scanner must never OOM on a giant page
UA = "Mozilla/5.0 (awscan/1.1 authorized-testing)"


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 3xx with its Location header instead of following


_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # scanners must read expired/self-signed lab targets


class Session:
    """Serial HTTP client with a cooperative rate limiter.

    ``delay`` defaults to 1.0s (production pacing); tests pass 0.
    Transport failures return negative statuses, never raise:
    -1 timeout, -2 remote disconnect, -3 connection/DNS error.
    """

    def __init__(self, delay=1.0, timeout=15, ua=UA, headers=None):
        self.delay, self.timeout = delay, timeout
        self.base_headers = {"User-Agent": ua, "Accept-Language": "en", "Accept": "*/*"}
        if headers:
            self.base_headers.update(headers)  # hunter auth: Cookie / Authorization / custom
        self._last = 0.0
        self.requests = 0
        self._opener = build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=_CTX))

    def _pace(self):
        gap = time.time() - self._last
        if gap < self.delay:
            time.sleep(self.delay - gap)
        self._last = time.time()

    @staticmethod
    def _resp(code, headers, raw):
        return Response(code, {k.lower(): v for k, v in (headers or {}).items()},
                        raw[:MAX_BODY].decode("utf-8", "replace"))

    def fetch(self, url, headers=None):
        self._pace()
        self.requests += 1
        req = Request(url, headers={**self.base_headers, **(headers or {})})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return self._resp(r.status, r.headers, r.read())
        except HTTPError as e:
            return self._resp(e.code, e.headers, e.read())
        except (socket.timeout, TimeoutError):
            return Response(-1)
        except http.client.RemoteDisconnected:
            return Response(-2)
        except Exception:
            return Response(-3)

    def timed_fetch(self, url, headers=None):
        """fetch + wall-clock latency — the currency of time-based detection."""
        t0 = time.monotonic()
        r = self.fetch(url, headers)
        return r, time.monotonic() - t0

    def post(self, url, body, ctype="application/json"):
        self._pace()
        self.requests += 1
        req = Request(url, data=body.encode("utf-8"),
                      headers={**self.base_headers, "Content-Type": ctype})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return self._resp(r.status, r.headers, r.read())
        except HTTPError as e:
            return self._resp(e.code, e.headers, e.read())
        except (socket.timeout, TimeoutError):
            return Response(-1)
        except Exception:
            return Response(-3)
