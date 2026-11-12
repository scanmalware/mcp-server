"""server.json is the MCP registry entry; it must describe the release the code reports.

The registry refuses a version it already has, so every publish bumps the version in
server.json, pyproject.toml and scanmalware_mcp/__init__.py together. The icon it
lists is served from the landing page directory and is the one serverInfo sends.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ICON = {"src": "https://mcp.scanmalware.com/icon.png", "mimeType": "image/png", "sizes": ["512x512"]}


class ReleaseMetadataTests(unittest.TestCase):
    def test_versions_agree(self) -> None:
        code = re.search(r'^__version__ = "([^"]+)"$', (ROOT / "scanmalware_mcp/__init__.py").read_text(), re.M)
        project = re.search(r'^version = "([^"]+)"$', (ROOT / "pyproject.toml").read_text(), re.M)
        published = json.loads((ROOT / "server.json").read_text())["version"]
        self.assertEqual({code.group(1), project.group(1), published}, {published})

    def test_registry_icon_is_served_and_matches_server_info(self) -> None:
        self.assertEqual(json.loads((ROOT / "server.json").read_text())["icons"], [ICON])
        icon = ROOT / "deploy/nginx/html/icon.png"
        self.assertEqual(icon.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        width, height = int.from_bytes(icon.read_bytes()[16:20], "big"), int.from_bytes(icon.read_bytes()[20:24], "big")
        self.assertEqual(f"{width}x{height}", ICON["sizes"][0])
        server = (ROOT / "scanmalware_mcp/server.py").read_text()
        self.assertIn(f'Icon(src="{ICON["src"]}", mime_type="{ICON["mimeType"]}", sizes={ICON["sizes"]!r})'.replace("'", '"'), server)


if __name__ == "__main__":
    unittest.main()
