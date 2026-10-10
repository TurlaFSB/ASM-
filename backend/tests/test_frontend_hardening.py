"""The web app must not depend on, or leak visits to, third-party hosts."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_index_html_loads_nothing_from_other_hosts():
    html = (ROOT / "frontend" / "index.html").read_text()
    assert not re.findall(r'(?:href|src)="https?://', html)


def test_csp_allows_only_own_origin_for_styles_and_fonts():
    conf = (ROOT / "frontend" / "nginx.conf").read_text()
    csp = re.search(r'Content-Security-Policy "([^"]+)"', conf).group(1)
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}
    for name in ("default-src", "script-src", "style-src", "font-src", "img-src"):
        assert not [v for v in directives[name] if v.startswith(("http:", "https:"))], f"{name}: {directives[name]}"
    assert directives["frame-ancestors"] == ["'none'"] and directives["object-src"] == ["'none'"]


def test_font_is_bundled_not_fetched():
    main = (ROOT / "frontend" / "src" / "main.jsx").read_text()
    assert "@fontsource/inter" in main
