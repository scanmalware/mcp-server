import datetime as dt
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("security_check", REPO / "deploy/security/security_check.py")
security_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security_check)


def access_line(path: str, status: int = 200) -> str:
    ts = dt.datetime.now(dt.timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'203.0.113.7 - - [{ts}] "GET {path} HTTP/1.1" {status} 74 "-" "crawler/1.0" '
            "host=mcp.scanmalware.com scheme=https\n")


class NginxPathTests(unittest.TestCase):
    def test_every_file_the_release_serves_is_expected(self):
        # The real html tree: what the landing build writes is meant to be served.
        served = security_check.served_paths(str(REPO))
        for path in ("/robots.txt", "/sitemap.xml", "/icon.png", "/og.png", "/theme.js", "/favicon.ico",
                     "/scanmalware.svg", "/en/", "/en/index.html", "/zh-cn/"):
            with self.subTest(path=path):
                self.assertIn(path, served)

    def test_only_unknown_paths_are_reported(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        html = tmp / security_check.HTML_DIR
        (html / "sv").mkdir(parents=True)
        (html / "index.html").write_text("x")
        (html / "robots.txt").write_text("x")
        (html / "sv" / "index.html").write_text("x")
        logs = tmp / "logs" / "nginx"
        logs.mkdir(parents=True)
        requests = ["/robots.txt", "/robots.txt?x=1", "/sv/", "/mcp", "/.well-known/mcp-registry-auth",
                    "/secret.txt", "/sv/../robots.txt", "/missing.png"]
        lines = [access_line(p) for p in requests] + [access_line("/nothing", 404)]
        (logs / "access.log").write_text("".join(lines))
        report = security_check.Report()
        since = dt.datetime.now(dt.timezone.utc).timestamp() - 3600
        security_check.check_nginx(report, str(tmp), since)
        flagged = sorted(text.split("unexpected path ")[1].split(" to ")[0] for _sev, text in report.lines())
        self.assertEqual(flagged, ["/missing.png", "/secret.txt", "/sv/../robots.txt"])


if __name__ == "__main__":
    unittest.main()
