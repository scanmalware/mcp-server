import importlib.util
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


path = Path(__file__).resolve().parents[2] / "deploy/mitmproxy/restrict_hosts.py"
spec = importlib.util.spec_from_file_location("restrict_hosts", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ProxyPolicyTests(unittest.TestCase):
    def setUp(self):
        # Refusals are logged to MITMPROXY_FULL_LOG; keep them out of the real path.
        self.log = Path(tempfile.mkdtemp()) / "full.log"
        env = patch.dict(os.environ, {"MITMPROXY_FULL_LOG": str(self.log)})
        env.start()
        self.addCleanup(env.stop)

    def flow(self, host, port=443, method="CONNECT"):
        return SimpleNamespace(
            id="flow-1",
            client_conn=SimpleNamespace(peername=("172.28.0.10", 50000)),
            request=SimpleNamespace(host=host, port=port, method=method),
            response=None,
        )

    def logged(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_scanmalware_hosts_remain_available(self):
        for host in ("scanmalware.com", "api.scanmalware.com", "SCANMALWARE.COM."):
            for method in ("CONNECT", "GET"):
                with self.subTest(host=host, method=method):
                    flow = self.flow(host, method=method)
                    policy.http_connect(flow) if method == "CONNECT" else policy.requestheaders(flow)
                    self.assertIsNone(flow.response)

    def test_other_destinations_rejected_before_connecting(self):
        for host in ("example.invalid", "scanmalware.com.example.invalid", "notscanmalware.com", "127.0.0.1", "::1"):
            for method in ("CONNECT", "GET"):
                with self.subTest(host=host, method=method):
                    flow = self.flow(host, method=method)
                    policy.http_connect(flow) if method == "CONNECT" else policy.requestheaders(flow)
                    self.assertEqual(flow.response.status_code, 403)

    def test_refusals_are_logged_including_https_connect(self):
        # A refused CONNECT never reaches log_full.py's response hook, so blocked
        # HTTPS destinations used to leave no trace at all.
        for method in ("CONNECT", "GET"):
            flow = self.flow("example.com", method=method)
            policy.http_connect(flow) if method == "CONNECT" else policy.requestheaders(flow)
        entries = self.logged()
        self.assertEqual([(e["event"], e["method"], e["host"], e["port"]) for e in entries], [
            ("proxy.blocked", "CONNECT", "example.com", 443),
            ("proxy.blocked", "GET", "example.com", 443),
        ])
        self.assertEqual(entries[0]["client"], ["172.28.0.10", 50000])
        self.assertEqual(entries[0]["id"], "flow-1")

    def test_allowed_destinations_are_not_logged_as_blocked(self):
        flow = self.flow("scanmalware.com")
        policy.http_connect(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(self.logged(), [])

    def test_unwritable_log_still_blocks(self):
        with patch.dict(os.environ, {"MITMPROXY_FULL_LOG": "/nonexistent-dir/full.log"}):
            flow = self.flow("example.com")
            policy.http_connect(flow)
        self.assertEqual(flow.response.status_code, 403)

    def test_non_web_ports_rejected(self):
        for port in (22, 3128, 8000):
            flow = self.flow("scanmalware.com", port)
            policy.http_connect(flow)
            self.assertEqual(flow.response.status_code, 403)
