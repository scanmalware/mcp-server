#!/usr/bin/env python3
"""Build the mcp.scanmalware.com landing page in every language.

template.html + strings.json -> ../html/index.html (English, served at /) and
../html/<code>/index.html for each language, the same URL scheme as
status.scanmalware.com (/en/, /sv/, /es/, /zh-cn/). nginx redirects / to a
visitor's browser language (deploy/nginx/nginx.conf, map $landing_lang).

  python3 deploy/nginx/landing/build.py           # write the pages
  python3 deploy/nginx/landing/build.py --check   # exit 1 if any page is stale

Strings are trusted HTML (links, <code>, <strong>), written by us; the few that
land in attributes are escaped. Commands, URLs and tool names stay in the
template so every language shows the same ones.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
HTML_DIR = HERE.parent / "html"
SITE = "https://mcp.scanmalware.com"
DEFAULT = "en"

# Light is the default; dark comes from the switch or the system setting, as on
# status.scanmalware.com. --logo turns the dark-text logo white on dark.
LIGHT = {
    "bg-a": "#f5f7ff",
    "bg-b": "#fef6e4",
    "card": "rgba(255, 255, 255, 0.9)",
    "text": "#0f172a",
    "muted": "#475569",
    "label": "#5f6368",
    "divider": "#e3e5e8",
    "line": "#e2e8f0",
    "tile": "#f8fafc",
    "chip": "#e2e8f0",
    "pre": "#0f172a",
    "pre-text": "#f8fafc",
    "link": "#2563eb",
    "button": "#2563eb",
    "button-hover": "#1d4ed8",
    "button-text": "#ffffff",
    "shadow": "rgba(15, 23, 42, 0.12)",
    "control": "#ffffff",
    "logo": "none",
    "sun": "none",
    "moon": "block",
}
DARK = {
    "bg-a": "#131416",
    "bg-b": "#191b20",
    "card": "#1c1d20",
    "text": "#e8eaed",
    "muted": "#9aa0a6",
    "label": "#9aa0a6",
    "divider": "#3c4043",
    "line": "#303236",
    "tile": "#232428",
    "chip": "#303236",
    "pre": "#0e0f11",
    "pre-text": "#e8eaed",
    "link": "#8ab4f8",
    "button": "#8ab4f8",
    "button-hover": "#aecbfa",
    "button-text": "#131416",
    "shadow": "rgba(0, 0, 0, 0.45)",
    "control": "#1c1d20",
    "logo": "brightness(0) invert(1)",
    "sun": "block",
    "moon": "none",
}
ATTRIBUTE_KEYS = ("meta_description", "language", "theme_toggle")


def _vars(values: dict[str, str], scheme: str, indent: str) -> str:
    lines = [f"{indent}--{name}: {value};" for name, value in values.items()]
    return "\n".join(lines + [f"{indent}color-scheme: {scheme};"])


def load_strings() -> dict[str, dict[str, str]]:
    strings = json.loads((HERE / "strings.json").read_text(encoding="utf-8"))
    expected = set(strings[DEFAULT])
    for code, table in strings.items():
        if set(table) != expected:
            missing, extra = sorted(expected - set(table)), sorted(set(table) - expected)
            raise SystemExit(f"strings.json: {code} differs from {DEFAULT}: missing {missing}, extra {extra}")
    return strings


def render(code: str, strings: dict[str, dict[str, str]]) -> str:
    table = dict(strings[code])
    for key in ATTRIBUTE_KEYS:
        table[key] = html.escape(table[key], quote=True)
    alternates = [
        f'    <link rel="alternate" hreflang="{t["html_lang"]}" href="{SITE}/{c}/" />' for c, t in strings.items()
    ]
    alternates.append(f'    <link rel="alternate" hreflang="x-default" href="{SITE}/" />')
    menu = []
    for c, t in strings.items():
        current = ' aria-current="true"' if c == code else ""
        menu.append(
            f'            <li><a href="/{c}/" hreflang="{t["html_lang"]}" lang="{t["html_lang"]}"{current}>'
            f"{html.escape(t['language_name'])}</a></li>"
        )
    template = Template((HERE / "template.html").read_text(encoding="utf-8"))
    return template.substitute(
        table,
        alternates="\n".join(alternates),
        language_menu="\n".join(menu),
        light_vars=_vars(LIGHT, "light", " " * 8),
        dark_vars=_vars(DARK, "dark", " " * 8),
    )


def sitemap(strings: dict[str, dict[str, str]]) -> str:
    # Every page lists every language version, as the pages' own hreflang links do.
    links = [
        f'    <xhtml:link rel="alternate" hreflang="{t["html_lang"]}" href="{SITE}/{c}/"/>' for c, t in strings.items()
    ]
    links.append(f'    <xhtml:link rel="alternate" hreflang="x-default" href="{SITE}/"/>')
    urls = [f"{SITE}/"] + [f"{SITE}/{c}/" for c in strings]
    body = "\n".join(f"  <url>\n    <loc>{u}</loc>\n" + "\n".join(links) + "\n  </url>" for u in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        f"{body}\n</urlset>\n"
    )


ROBOTS = f"""# mcp.scanmalware.com: the landing page, in every language. /mcp is the MCP endpoint, not a page.
User-agent: *
Disallow: /mcp
Allow: /

Sitemap: {SITE}/sitemap.xml
"""


def outputs() -> dict[Path, str]:
    strings = load_strings()
    pages = {HTML_DIR / "index.html": render(DEFAULT, strings)}
    for code in strings:
        pages[HTML_DIR / code / "index.html"] = render(code, strings)
    pages[HTML_DIR / "sitemap.xml"] = sitemap(strings)
    pages[HTML_DIR / "robots.txt"] = ROBOTS
    return pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a generated page differs from the sources")
    args = parser.parse_args()
    stale = []
    for path, text in outputs().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        stale.append(path.relative_to(HERE.parent.parent.parent))
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if args.check and stale:
        print("stale, run deploy/nginx/landing/build.py: " + ", ".join(map(str, stale)), file=sys.stderr)
        return 1
    print(("stale: " if args.check else "wrote: ") + (", ".join(map(str, stale)) or "nothing"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
