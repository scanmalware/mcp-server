"""The mcp.scanmalware.com landing page in every language stays in step with its sources.

deploy/nginx/landing/build.py writes deploy/nginx/html/index.html and
deploy/nginx/html/<code>/index.html from template.html and strings.json. A hand edit
to a generated page, or a strings change without a rebuild, would ship one language
out of date; a translation that drops or changes a link would send that language's
readers somewhere else. nginx.conf redirects / to each language's page, so every
language needs a redirect and every redirect needs a page.
"""

import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANDING = ROOT / "deploy" / "nginx" / "landing"
HTML = ROOT / "deploy" / "nginx" / "html"
NGINX = ROOT / "deploy" / "nginx" / "nginx.conf"

spec = importlib.util.spec_from_file_location("landing_build", LANDING / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class LandingPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.strings = json.loads((LANDING / "strings.json").read_text(encoding="utf-8"))

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
                self.assertIn(f'<html lang="{table["html_lang"]}">', page)
                self.assertIn('hreflang="x-default" href="https://mcp.scanmalware.com/"', page)
                self.assertEqual(page.count('aria-current="true"'), 1)
                for other in self.strings:
                    self.assertIn(f'<a href="/{other}/"', page)

    def test_nginx_redirects_to_exactly_the_built_languages(self) -> None:
        conf = NGINX.read_text(encoding="utf-8")
        block = re.search(r"map \$http_accept_language \$landing_lang \{(.*?)\}", conf, re.S)
        self.assertIsNotNone(block)
        targets = set(re.findall(r'~\*\^\S+\s+"([^"]+)";', block.group(1)))
        self.assertEqual(targets, set(self.strings) - {build.DEFAULT})
        root = re.search(r"location = / \{(.*?)\n    \}", conf, re.S).group(1)
        # add_header in a location replaces the server-level set: HSTS must be repeated.
        self.assertIn('add_header Strict-Transport-Security "max-age=31536000" always;', root)
        self.assertIn('add_header Vary "Accept-Language" always;', root)


if __name__ == "__main__":
    unittest.main()
