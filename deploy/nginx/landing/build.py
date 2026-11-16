#!/usr/bin/env python3
"""Build the mcp.scanmalware.com landing page in every language.

template.html + locales/<code>.json -> ../html/index.html (English, served at /)
and ../html/<code>/index.html for each language, the same URL scheme as
status.scanmalware.com (/en/, /sv/, /es/, /zh-cn/). nginx redirects / to a
visitor's browser language: the map $landing_lang block in ../nginx.conf is
generated here too, from each language's accept_language.

  python3 deploy/nginx/landing/build.py                    # write the pages and the nginx map
  python3 deploy/nginx/landing/build.py --check            # exit 1 if anything is stale
  python3 deploy/nginx/landing/build.py --validate xx.json # check one translation, write nothing

Adding a language is one file, locales/<code>.json: see locales/README.md.

Strings are HTML (links, <code>, <strong>). A translation may come from someone
without access to this repo, so every string must carry exactly the tags of the
English one; the few that land in attributes are escaped. Commands, URLs and tool
names stay in the template so every language shows the same ones.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
LOCALES = HERE / "locales"
HTML_DIR = HERE.parent / "html"
NGINX_CONF = HERE.parent / "nginx.conf"
SITE = "https://mcp.scanmalware.com"
DEFAULT = "en"
# Link previews (Open Graph, X cards): one image for every language, rendered from og/card.html.
OG_IMAGE = f"{SITE}/og.png"

# Per-language settings in locales/<code>.json, beside the translated strings. They end up in
# URLs, HTML attributes and nginx.conf, so each has a strict shape.
CODE = re.compile(r"[a-z]{2,3}(-[a-z0-9]{2,8})*")  # the file name and the URL: /sv/, /zh-cn/
SETTINGS = {
    "html_lang": re.compile(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*"),  # BCP 47: sv, zh-CN, pt-BR
    "dir": re.compile(r"ltr|rtl"),
    "og_locale": re.compile(r"[a-z]{2,3}_[A-Z]{2}"),  # Open Graph: sv_SE, zh_CN
}
# Accept-Language prefixes that redirect / to this language, lowercase: ["zh"], ["pt-br"].
ACCEPT_LANGUAGE = "accept_language"
TAG = re.compile(r"<[^<>]*>")
INLINE_CODE = re.compile(r"<code>(.*?)</code>")
MAP_BLOCK = re.compile(
    r"(?<=# BEGIN landing languages\n).*?(?=  # END landing languages\n)",
    re.S,
)

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


def read_locale(path: Path) -> dict:
    table = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(table, dict):
        raise SystemExit(f"{path.name}: expected one JSON object of key: string")
    return table


def problems(code: str, table: dict, english: dict) -> list[str]:
    """Everything wrong with one language's table, as messages a translator can act on."""
    found = []
    if not CODE.fullmatch(code):
        found.append(f"file name {code!r}: use a lowercase language code such as sv or pt-br")
    missing, extra = sorted(set(english) - set(table)), sorted(set(table) - set(english))
    if missing:
        found.append(f"missing keys: {', '.join(missing)}")
    if extra:
        found.append(f"keys that {DEFAULT}.json does not have: {', '.join(extra)}")
    for key, source in english.items():
        if key not in table:
            continue
        value = table[key]
        if key == ACCEPT_LANGUAGE:
            if not (
                isinstance(value, list)
                and value
                and all(isinstance(v, str) and CODE.fullmatch(v) for v in value)
            ):
                found.append(f'{key}: expected a list of lowercase language prefixes such as ["pt-br"]')
            continue
        if not isinstance(value, str) or not value.strip():
            found.append(f"{key}: expected a non-empty string")
            continue
        if key in SETTINGS:
            if not SETTINGS[key].fullmatch(value):
                found.append(f"{key}: {value!r} does not look like {SETTINGS[key].pattern}")
            continue
        if key in ATTRIBUTE_KEYS or key == "language_name":
            continue  # escaped where they are used
        tags = TAG.findall(value)
        if sorted(tags) != sorted(TAG.findall(source)) or value.count("<") != len(tags) or value.count(">") != len(tags):
            found.append(
                f"{key}: the HTML tags must be exactly those of the English string "
                f"({' '.join(TAG.findall(source)) or 'none'}); write a literal < or > as &lt; or &gt;"
            )
        elif sorted(INLINE_CODE.findall(value)) != sorted(INLINE_CODE.findall(source)):
            found.append(f"{key}: leave the text inside <code>...</code> as it is in English")
    return found


def load_strings() -> dict[str, dict]:
    """Every language in locales/, English first and the rest by code; exits on any problem."""
    paths = {path.stem: path for path in LOCALES.glob("*.json")}
    if DEFAULT not in paths:
        raise SystemExit(f"locales/{DEFAULT}.json is missing")
    order = [DEFAULT] + sorted(code for code in paths if code != DEFAULT)
    strings = {code: read_locale(paths[code]) for code in order}
    found = [f"locales/{code}.json: {p}" for code, t in strings.items() for p in problems(code, t, strings[DEFAULT])]
    claimed: dict[str, str] = {}
    for code, table in strings.items():
        if code == DEFAULT or not isinstance(table.get(ACCEPT_LANGUAGE), list):
            continue
        for prefix in table[ACCEPT_LANGUAGE]:
            if isinstance(prefix, str) and claimed.setdefault(prefix, code) != code:
                found.append(f"locales/{code}.json: {ACCEPT_LANGUAGE} {prefix!r} is already taken by {claimed[prefix]}")
    if found:
        raise SystemExit("\n".join(found))
    return strings


def nginx_map(strings: dict[str, dict]) -> str:
    # nginx takes the first regex that matches, so the longer prefix goes first: zh-tw before zh.
    # The prefix must end the language subtag: fi is not fil.
    pairs = sorted(
        ((prefix, code) for code, t in strings.items() if code != DEFAULT for prefix in t[ACCEPT_LANGUAGE]),
        key=lambda pair: (-len(pair[0]), pair[0]),
    )
    lines = ["  map $http_accept_language $landing_lang {", '    default "";']
    lines += [f'    "~*^{prefix}(?![a-z0-9])" "{code}";' for prefix, code in pairs]
    return "\n".join(lines + ["  }"]) + "\n"


def nginx_conf(strings: dict[str, dict]) -> str:
    conf = NGINX_CONF.read_text(encoding="utf-8")
    if not MAP_BLOCK.search(conf):
        raise SystemExit("nginx.conf: the '# BEGIN landing languages' ... '# END landing languages' markers are missing")
    return MAP_BLOCK.sub(lambda _: nginx_map(strings), conf, count=1)


def render(code: str, strings: dict[str, dict], path: str | None = None) -> str:
    # path is where the page is served: "/" for the default-language copy, else "/<code>/".
    table = {key: value for key, value in strings[code].items() if isinstance(value, str)}
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
    og_alternates = [
        f'    <meta property="og:locale:alternate" content="{t["og_locale"]}" />' for c, t in strings.items() if c != code
    ]
    template = Template((HERE / "template.html").read_text(encoding="utf-8"))
    return template.substitute(
        table,
        page_url=SITE + (path or f"/{code}/"),
        og_locale_alternates="\n".join(og_alternates),
        og_image=OG_IMAGE,
        alternates="\n".join(alternates),
        language_menu="\n".join(menu),
        light_vars=_vars(LIGHT, "light", " " * 8),
        dark_vars=_vars(DARK, "dark", " " * 8),
    )


def sitemap(strings: dict[str, dict]) -> str:
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
    pages = {HTML_DIR / "index.html": render(DEFAULT, strings, "/")}
    for code in strings:
        pages[HTML_DIR / code / "index.html"] = render(code, strings)
    pages[HTML_DIR / "sitemap.xml"] = sitemap(strings)
    pages[HTML_DIR / "robots.txt"] = ROBOTS
    pages[NGINX_CONF] = nginx_conf(strings)
    return pages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a generated page differs from the sources")
    parser.add_argument("--validate", metavar="FILE", type=Path, help="check one <code>.json translation and exit")
    args = parser.parse_args()
    if args.validate:
        found = problems(args.validate.stem, read_locale(args.validate), read_locale(LOCALES / f"{DEFAULT}.json"))
        print("\n".join(found) or f"{args.validate.name}: ok")
        return 1 if found else 0
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
