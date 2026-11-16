"""The mcp.scanmalware.com landing page in every language stays in step with its sources.

deploy/nginx/landing/build.py writes deploy/nginx/html/index.html and
deploy/nginx/html/<code>/index.html from template.html and locales/<code>.json. A hand
edit to a generated page, or a strings change without a rebuild, would ship one language
out of date; a translation that drops or changes a link would send that language's
readers somewhere else. nginx.conf redirects / to each language's page, so every
language needs a redirect and every redirect needs a page: build.py writes that map too.

A new language is one file dropped into locales/, and it may be written by someone who
cannot see this repo, so build.py has to refuse a file that would put new markup on the
page or new text into nginx.conf.
"""

import importlib.util
import json
import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
LANDING = ROOT / "deploy" / "nginx" / "landing"
HTML = ROOT / "deploy" / "nginx" / "html"
NGINX = ROOT / "deploy" / "nginx" / "nginx.conf"

spec = importlib.util.spec_from_file_location("landing_build", LANDING / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class LandingPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.strings = build.load_strings()

    def test_generated_pages_are_current(self) -> None:
        for path, text in build.outputs().items():
            with self.subTest(page=str(path.relative_to(ROOT))):
                self.assertTrue(path.exists(), "run deploy/nginx/landing/build.py")
                self.assertEqual(path.read_text(encoding="utf-8"), text, "run deploy/nginx/landing/build.py")

    def test_every_language_has_the_same_links_and_commands(self) -> None:
        def parts(code: str) -> tuple[list[str], list[str]]:
            page = (HTML / code / "index.html").read_text(encoding="utf-8")
            body = page[page.index("<main>") :]
            return sorted(re.findall(r'href="([^"]+)"', body)), re.findall(r"<pre><code>(.*?)</code></pre>", body, re.S)

        english = parts(build.DEFAULT)
        for code in self.strings:
            with self.subTest(language=code):
                self.assertEqual(parts(code), english)

    def test_every_page_offers_every_language(self) -> None:
        for code, table in self.strings.items():
            page = (HTML / code / "index.html").read_text(encoding="utf-8")
            with self.subTest(language=code):
                self.assertIn(f'<html lang="{table["html_lang"]}" dir="{table["dir"]}">', page)
                self.assertIn('hreflang="x-default" href="https://mcp.scanmalware.com/"', page)
                self.assertEqual(page.count('aria-current="true"'), 1)
                for other in self.strings:
                    self.assertIn(f'<a href="/{other}/"', page)

    def test_every_page_has_a_link_preview_image(self) -> None:
        # Until 2026-11-13 a shared link to mcp.scanmalware.com showed no picture: no og: or
        # twitter: tags. og.png is rendered from landing/og/card.html.
        data = (HTML / "og.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (1200, 630))
        self.assertLess(len(data), 300_000)
        pages = {"index.html": "/"} | {f"{code}/index.html": f"/{code}/" for code in self.strings}
        for name, path in pages.items():
            page = (HTML / name).read_text(encoding="utf-8")
            with self.subTest(page=name):
                self.assertIn('<meta property="og:image" content="https://mcp.scanmalware.com/og.png" />', page)
                self.assertIn('<meta name="twitter:card" content="summary_large_image" />', page)
                self.assertIn(f'<meta property="og:url" content="https://mcp.scanmalware.com{path}" />', page)

    def test_sitemap_and_robots_cover_every_language(self) -> None:
        sitemap = (HTML / "sitemap.xml").read_text(encoding="utf-8")
        locs = re.findall(r"<loc>([^<]+)</loc>", sitemap)
        self.assertEqual(locs, ["https://mcp.scanmalware.com/"] + [f"https://mcp.scanmalware.com/{c}/" for c in self.strings])
        robots = (HTML / "robots.txt").read_text(encoding="utf-8")
        self.assertIn("Disallow: /mcp\n", robots)
        self.assertIn("Sitemap: https://mcp.scanmalware.com/sitemap.xml", robots)

    def test_nginx_redirects_to_exactly_the_built_languages(self) -> None:
        conf = NGINX.read_text(encoding="utf-8")
        block = re.search(r"map \$http_accept_language \$landing_lang \{(.*?)\}", conf, re.S)
        self.assertIsNotNone(block)
        targets = set(re.findall(r'"~\*\^[^"]+"\s+"([^"]+)";', block.group(1)))
        self.assertEqual(targets, set(self.strings) - {build.DEFAULT})
        root = re.search(r"location = / \{(.*?)\n    \}", conf, re.S).group(1)
        # add_header in a location replaces the server-level set: HSTS must be repeated.
        self.assertIn('add_header Strict-Transport-Security "max-age=31536000" always;', root)
        self.assertIn('add_header Vary "Accept-Language" always;', root)

    def test_a_translation_cannot_change_markup_or_settings(self) -> None:
        english = self.strings[build.DEFAULT]
        self.assertEqual(build.problems("sv", self.strings["sv"], english), [])
        bad = {
            "lead": english["lead"] + "<script src=//x.example></script>",
            "item_cli": english["item_cli"].replace("github.com/scanmalware", "github.com/someone-else"),
            "footer_source": "Source <img src=x onerror=alert(1)",  # closed by the template's own >
            "visibility_text": english["visibility_text"].replace("<code>public</code>", "<code>offentlig</code>"),
            "get_it": "",
            "og_locale": 'xx_XX" /><script>',
            "dir": "sideways",
            "html_lang": 'xx"><script>',
            "accept_language": ['xx" "en"; include /etc/passwd; "'],
        }
        for key, value in bad.items():
            with self.subTest(key=key):
                found = build.problems("xx", english | {key: value}, english)
                self.assertEqual(len(found), 1, found)
                self.assertTrue(found[0].startswith(key + ":"), found)
        self.assertTrue(build.problems("../xx", english, english))
        self.assertTrue(build.problems("xx", {k: v for k, v in english.items() if k != "lead"}, english))
        self.assertTrue(build.problems("xx", english | {"new_key": "x"}, english))

    def test_a_new_language_is_one_file(self) -> None:
        # Nothing but locales/<code>.json: the page, the menu entry on every other page, the
        # hreflang and og:locale alternates, the sitemap and the nginx redirect follow from it.
        with tempfile.TemporaryDirectory() as tmp:
            locales = Path(tmp) / "locales"
            shutil.copytree(LANDING / "locales", locales)
            new = self.strings[build.DEFAULT] | {
                "html_lang": "ar",
                "language_name": "العربية",
                "dir": "rtl",
                "og_locale": "ar_SA",
                "accept_language": ["ar"],
            }
            (locales / "ar.json").write_text(json.dumps(new, ensure_ascii=False), encoding="utf-8")
            taken = self.strings["sv"] | {"accept_language": ["ar"]}
            with mock.patch.object(build, "LOCALES", locales):
                pages = build.outputs()
                (locales / "sv.json").write_text(json.dumps(taken, ensure_ascii=False), encoding="utf-8")
                with self.assertRaises(SystemExit) as two_languages_one_prefix:
                    build.load_strings()
        self.assertIn("already taken", str(two_languages_one_prefix.exception))
        self.assertIn('<html lang="ar" dir="rtl">', pages[HTML / "ar" / "index.html"])
        english_page = pages[HTML / "en" / "index.html"]
        self.assertIn('<li><a href="/ar/" hreflang="ar" lang="ar">العربية</a></li>', english_page)
        self.assertIn('<link rel="alternate" hreflang="ar" href="https://mcp.scanmalware.com/ar/" />', english_page)
        self.assertIn('<meta property="og:locale:alternate" content="ar_SA" />', english_page)
        self.assertIn("<loc>https://mcp.scanmalware.com/ar/</loc>", pages[HTML / "sitemap.xml"])
        self.assertIn('    "~*^ar(?![a-z0-9])" "ar";\n', pages[NGINX])
        # Only the map changes in nginx.conf.
        outside = lambda conf: build.MAP_BLOCK.sub("", conf)  # noqa: E731
        self.assertEqual(outside(pages[NGINX]), outside(NGINX.read_text(encoding="utf-8")))

    def test_the_longer_accept_language_prefix_is_matched_first(self) -> None:
        strings = {
            "en": {"accept_language": ["en"]},
            "zh-cn": {"accept_language": ["zh"]},
            "zh-tw": {"accept_language": ["zh-tw", "zh-hk"]},
        }
        targets = re.findall(r'"\s+"([^"]+)";', build.nginx_map(strings))
        self.assertEqual(targets, ["zh-tw", "zh-tw", "zh-cn"])


if __name__ == "__main__":
    unittest.main()
