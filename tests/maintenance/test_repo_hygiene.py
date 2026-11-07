"""Production logs, captures and keys must never be committed.

The repository is public, and the server's logs hold client IPs, tool arguments and
results, raw HTTP bodies and proxy traffic. They live only on the droplet
(/opt/scanmalware-mcp/logs and /var/log/scanmalware-mcp-archive). This test fails CI if
a tracked file looks like one of them, whatever its name.
"""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_PATHS = re.compile(
    r"(^|/)logs?/"
    r"|(^|/)log-archive/|scanmalware-mcp-archive"
    r"|\.log(\.[0-9]+)?(\.gz)?$"
    r"|\.(zst|gz|xz|bz2|pcap|pcapng|har|mp4|p12|pfx|key|pem|crt|cer|der)$"
    r"|(^|/)\.env($|\.)"
    r"|^deploy/mitmproxy/state/(?!\.gitkeep$)"
    r"|^deploy/nginx/html/demo/"
)

# A few lines in any of these shapes means log output was pasted or copied in.
LOG_LINE_SHAPES = {
    "MCP log": re.compile(rb"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} (DEBUG|INFO|WARNING|ERROR|CRITICAL) \S+ \{"),
    "Nginx access log": re.compile(rb'^\S+ - \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "'),
    "Nginx error log": re.compile(rb"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(error|warn|notice|crit|alert|emerg)\] "),
    "proxy log": re.compile(rb'^\{"client": \{"connected_at": '),
    "audit log": re.compile(rb"^type=\w+ msg=audit\(\d+\.\d+:\d+\)"),
    "journal": re.compile(rb"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} scanmalware-mcp"),
}
MAX_LOG_LINES = 2
PRIVATE_KEY = re.compile(rb"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----")
MAX_BYTES = 1_500_000  # the largest tracked file today, a lock file, is ~60 KB


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [name for name in out.decode().split("\0") if name]


class RepoHygieneTests(unittest.TestCase):
    def setUp(self):
        self.files = tracked_files()
        if self.files is None:
            self.skipTest("not a git checkout")

    def test_no_log_capture_key_or_private_data_paths(self):
        bad = [f for f in self.files if FORBIDDEN_PATHS.search(f)]
        self.assertEqual(bad, [], "logs, captures, keys or droplet-only files are tracked")

    def test_no_file_contains_log_lines_or_private_keys(self):
        problems = []
        for name in self.files:
            path = ROOT / name
            if not path.is_file():
                continue
            data = path.read_bytes()
            if len(data) > MAX_BYTES:
                problems.append(f"{name}: {len(data)} bytes, too large for source")
                continue
            if PRIVATE_KEY.search(data):
                problems.append(f"{name}: private key")
            lines = data.splitlines()
            for label, shape in LOG_LINE_SHAPES.items():
                hits = sum(1 for line in lines if shape.match(line))
                if hits > MAX_LOG_LINES:
                    problems.append(f"{name}: {hits} lines of {label} output")
        self.assertEqual(problems, [])

    def test_the_patterns_catch_real_log_shapes(self):
        samples = {
            "MCP log": b'2026-11-07 10:48:13,434 INFO scanmalware_mcp.http {"body": {}}',
            "Nginx access log": b'1.2.3.4 - - [07/Nov/2026:00:04:43 +0000] "POST /mcp HTTP/1.1" 200 197',
            "Nginx error log": b"2026/11/07 11:46:37 [error] 30#30: *1 connect() failed",
            "proxy log": b'{"client": {"connected_at": 1793923699.26, "peername": ["172.28.0.10", 1]}}',
            "audit log": b"type=SYSCALL msg=audit(1794052054.985:197321): arch=c000003e",
            "journal": b"2026-11-06T07:05:56+0000 scanmalware-mcp-small sshd[550824]: Accepted publickey",
        }
        for label, line in samples.items():
            self.assertTrue(LOG_LINE_SHAPES[label].match(line), label)
        for name in ["logs/mcp/mcp.log", "x/mcp-http.log.12", "nginx/access.log.3.gz", "a.pcap",
                     "deploy/.env", ".env.production", "deploy/mitmproxy/state/mitmproxy-ca.pem",
                     "deploy/nginx/html/demo/video.mp4", "archive/mcp-http.log.x.zst"]:
            self.assertTrue(FORBIDDEN_PATHS.search(name), name)
        for name in ["deploy/logrotate/archive_logs.py", "docs/OPERATIONS.md",
                     "deploy/mitmproxy/state/.gitkeep", "deploy/nginx/html/.well-known/openai-apps-challenge"]:
            self.assertFalse(FORBIDDEN_PATHS.search(name), name)


if __name__ == "__main__":
    unittest.main()
