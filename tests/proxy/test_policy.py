import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


path = Path(__file__).resolve().parents[2] / "deploy/mitmproxy/restrict_hosts.py"
spec = importlib.util.spec_from_file_location("restrict_hosts", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ProxyPolicyTests(unittest.TestCase):
    def flow(self, host, port=443, method="CONNECT"):
        return SimpleNamespace(
            request=SimpleNamespace(host=host, port=port, method=method), response=None
        )

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

    def test_non_web_ports_rejected(self):
        for port in (22, 3128, 8000):
            flow = self.flow("scanmalware.com", port)
            policy.http_connect(flow)
            self.assertEqual(flow.response.status_code, 403)
