"""HTTP session: rate-limited, redirect-transparent, failure-tolerant."""
import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


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

    def __init__(self, delay=1.0, timeout=15, ua="Mozilla/5.0 (awscan/1.0)"):
        self.delay, self.timeout, self.ua = delay, timeout, ua
        self._last = 0.0
        self.requests = 0
        opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=_CTX))
        opener.addheaders = [("User-Agent", ua), ("Accept-Language", "en")]
        self._opener = opener

    def _pace(self):
        gap = time.time() - self._last
        if gap < self.delay:
            time.sleep(self.delay - gap)
        self._last = time.time()

    def fetch(self, url):
        self._pace()
        self.requests += 1
        try:
            with self._opener.open(url, timeout=self.timeout) as r:
                return Response(r.status, {k.lower(): v for k, v in r.headers.items()},
                                r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()},
                            e.read().decode("utf-8", "replace"))
        except (socket.timeout, TimeoutError):
            return Response(-1)
        except http.client.RemoteDisconnected:
            return Response(-2)
        except Exception:
            return Response(-3)
