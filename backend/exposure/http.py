"""Tiny outbound HTTP client for collectors: fixed host allow-list, no redirects, size and time bounds."""
import json as _json
from dataclasses import dataclass
from typing import Dict, Optional

import requests

from backend.exposure.base import CollectorError

ALLOWED_HOSTS = {"api.github.com", "api.xposedornot.com", "ahmia.fi"}
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = (5, 20)
USER_AGENT = "ASM-Platform-Exposure/1"


@dataclass
class Response:
    status: int
    body: bytes
    headers: Dict[str, str]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return _json.loads(self.body.decode("utf-8", errors="replace"))


class HttpClient:
    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> Response:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        if host not in ALLOWED_HOSTS or not url.startswith("https://"):
            raise CollectorError("blocked host")
        h = {"User-Agent": USER_AGENT, **(headers or {})}
        try:
            with requests.get(url, params=params, headers=h, timeout=TIMEOUT, allow_redirects=False, stream=True) as r:
                buf = b""
                for chunk in r.iter_content(65536):
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise CollectorError("response too large")
                return Response(r.status_code, buf, {k.lower(): v for k, v in r.headers.items()})
        except CollectorError:
            raise
        except requests.exceptions.Timeout:
            raise CollectorError("timeout")
        except requests.exceptions.SSLError:
            raise CollectorError("tls error")
        except requests.exceptions.RequestException:
            raise CollectorError("connection error")
