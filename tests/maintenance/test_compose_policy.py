"""Compose settings that the security monitoring depends on."""

import re
import unittest
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[2] / "deploy/docker-compose.yml"


def service_block(text: str, name: str) -> str:
    """Return one service's lines: from "  <name>:" to the next two-space key."""
    match = re.search(rf"^  {name}:\n((?:(?:    .*)?\n)*)", text, re.M)
    if not match:
        raise AssertionError(f"service {name} not found")
    return match.group(1)


class ComposePolicyTests(unittest.TestCase):
    def setUp(self):
        self.text = COMPOSE.read_text()

    def test_mcp_container_has_no_healthcheck(self):
        # auditd reports every program started as UID 10001 (the mcp container's
        # user) as possible code execution. A healthcheck would start one every
        # interval and bury real findings, so readiness is probed from nginx.
        self.assertNotIn("healthcheck:", service_block(self.text, "mcp"))

    def test_nginx_healthcheck_probes_mcp(self):
        nginx = service_block(self.text, "nginx")
        self.assertIn("healthcheck:", nginx)
        self.assertIn("http://mcp:8000/mcp", nginx)
        self.assertIn("= 405", nginx)


if __name__ == "__main__":
    unittest.main()
