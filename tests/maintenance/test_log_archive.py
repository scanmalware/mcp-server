import datetime as dt
import gzip
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "deploy/logrotate/archive_logs.py"
spec = importlib.util.spec_from_file_location("archive_logs", path)
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)

UTC = dt.timezone.utc
MCP = "2026-11-07 10:48:13,434 INFO scanmalware_mcp.http {\"event\": \"x\"}\n"


@unittest.skipIf(shutil.which("zstd") is None, "zstd is not installed")
class LogArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.logs = self.tmp / "logs"
        self.out = self.tmp / "archive"
        self.logs.mkdir()
        self.sources = [("mcp", self.logs, "mcp-http.log"), ("nginx", self.logs, "access.log")]

    def write(self, name, text):
        (self.logs / name).write_text(text)

    def archived(self):
        return sorted(p for p in self.out.rglob("*.zst"))

    def test_only_rotated_files_are_archived_once_however_they_move(self):
        self.write("mcp-http.log", "2026-11-07 11:00:00,000 INFO live\n")
        self.write("mcp-http.log.1", MCP + "second line\n")
        stats = archive.run(self.sources, self.out, 365, dt.datetime(2026, 11, 7, tzinfo=UTC))
        self.assertEqual(stats["archived"], 1)
        [only] = self.archived()
        self.assertEqual(only.parent, self.out / "mcp" / "2026" / "11")
        self.assertTrue(only.name.startswith("mcp-http.log.20261107T104813Z."))
        content = subprocess.run(["zstd", "-dc", str(only)], capture_output=True, check=True).stdout
        self.assertEqual(content.decode(), MCP + "second line\n")

        # A later rotation renames .1 to .2; the segment must not be stored twice.
        os.rename(self.logs / "mcp-http.log.1", self.logs / "mcp-http.log.2")
        stats = archive.run(self.sources, self.out, 365, dt.datetime(2026, 11, 7, tzinfo=UTC))
        self.assertEqual(stats["archived"], 0)
        self.assertEqual(len(self.archived()), 1)

    def test_logrotate_recompression_is_the_same_segment(self):
        line = '1.2.3.4 - - [07/Nov/2026:00:04:43 +0000] "POST /mcp HTTP/1.1" 200 197\n'
        self.write("access.log.1", line)
        archive.run(self.sources, self.out, 365, dt.datetime(2026, 11, 8, tzinfo=UTC))
        os.remove(self.logs / "access.log.1")
        with gzip.open(self.logs / "access.log.2.gz", "wt") as fh:
            fh.write(line)
        stats = archive.run(self.sources, self.out, 365, dt.datetime(2026, 11, 8, tzinfo=UTC))
        self.assertEqual(stats["archived"], 0)
        [only] = self.archived()
        self.assertIn(".20261107T000443Z.", only.name)

    def test_empty_and_unrelated_files_are_skipped(self):
        self.write("access.log.1", "")
        self.write("mcp-http.log.bak", MCP)
        self.write("other.log.1", MCP)
        self.assertEqual(archive.run(self.sources, self.out, 365)["archived"], 0)

    def test_archives_past_retention_are_pruned(self):
        old = self.out / "mcp" / "2025" / "10" / "mcp-http.log.20251001T000000Z.0123456789abcdef.zst"
        new = self.out / "mcp" / "2026" / "10" / "mcp-http.log.20261101T000000Z.0123456789abcdef.zst"
        for p in (old, new):
            p.parent.mkdir(parents=True)
            p.write_bytes(b"")
        stats = archive.run(self.sources, self.out, 365, dt.datetime(2026, 11, 7, tzinfo=UTC))
        self.assertEqual(stats["pruned"], 1)
        self.assertFalse(old.exists())
        self.assertTrue(new.exists())

    def test_first_line_times_for_every_kept_format(self):
        cases = {
            b"2026-11-07 10:48:13,434 INFO scanmalware_mcp {}": "2026-11-07T10:48:13",
            b"2026/11/07 11:46:37 [error] 30#30: *1 connect() failed": "2026-11-07T11:46:37",
            b'1.2.3.4 - - [07/Nov/2026:01:04:43 +0100] "GET / HTTP/1.1"': "2026-11-07T00:04:43",
            b"type=SYSCALL msg=audit(1794052054.985:197321): arch=c000003e": "2026-11-07T11:47:34",
            b'{"client": {"connected_at": 1793923699.2626085, "peername": []}}': "2026-11-06T00:08:19",
        }
        for line, expected in cases.items():
            self.assertEqual(archive.first_line_time(line).strftime("%Y-%m-%dT%H:%M:%S"), expected)
        self.assertIsNone(archive.first_line_time(b"no timestamp here"))


if __name__ == "__main__":
    unittest.main()
