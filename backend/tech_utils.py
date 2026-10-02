"""Clean WhatWeb technology lists for display (UI and reports).

WhatWeb reports both "Jetty" and "Jetty:8.1.7", plus plugin noise that is not a technology
(Cookies, HttpOnly, security headers). Display code keeps the most informative form only.
"""
from typing import Iterable, List, Optional

NOISE = {"cookies", "httponly", "httpserver", "index-of", "x-frame-options", "x-xss-protection",
         "x-powered-by", "country", "ip", "uncommonheaders", "strict-transport-security",
         "content-type", "html5", "script"}


def clean_technologies(items: Optional[Iterable[str]]) -> List[str]:
    items = [str(t).strip() for t in (items or []) if t and str(t).strip()]
    items = [t for t in items if t.split(":")[0].lower() not in NOISE]
    items = [("Apache:" + t.split(":", 1)[1]) if t.startswith("Apache HTTP Server:") else t for t in items]
    versioned = {t.split(":")[0].lower() for t in items if ":" in t}
    out, seen = [], set()
    for t in items:
        if ":" not in t and t.lower() in versioned:
            continue                      # bare name superseded by its versioned form
        if "apache http server" == t.lower() and any(x.startswith("Apache") for x in items if x != t):
            continue
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
