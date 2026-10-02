import datetime as dt
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / "deploy/check_proxy_audit.py"
spec = importlib.util.spec_from_file_location("audit_policy", path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class AuditPolicyTests(unittest.TestCase):
    baseline = {"review_by": "2026-11-02", "packages": {"example": {"version": "1.0", "ids": ["GHSA-known"]}}}

    def test_known_alias_is_reported_but_new_advisory_fails(self):
        report = {"dependencies": [{"name": "example", "version": "1.0", "vulns": [{"id": "CVE-known", "aliases": ["GHSA-known"]}]}]}
        self.assertEqual(policy.check(report, self.baseline, dt.date(2026, 10, 2)), [])
        report["dependencies"][0]["vulns"].append({"id": "CVE-new"})
        self.assertEqual(len(policy.check(report, self.baseline, dt.date(2026, 10, 2))), 1)

    def test_changed_version_and_expired_review_fail(self):
        report = {"Results": [{"Vulnerabilities": [{"PkgName": "example", "InstalledVersion": "1.0", "VulnerabilityID": "GHSA-known", "FixedVersion": "2.0", "Severity": "HIGH"}]}]}
        self.assertTrue(policy.check(report, self.baseline, dt.date(2026, 11, 2)))
        report["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1.1"
        self.assertTrue(policy.check(report, self.baseline, dt.date(2026, 10, 2)))

    def test_invalid_report_is_not_a_clean_audit(self):
        with self.assertRaises(ValueError):
            policy.findings({"error": "scanner unavailable"})
