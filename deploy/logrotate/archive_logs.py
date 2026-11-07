#!/usr/bin/env python3
"""Keep every rotated ScanMalware MCP log in a compressed archive for a year.

The MCP container rotates its own logs by size (``mcp-http.log.1`` .. ``.112``), and at
the November 2026 volume that keeps only about two days of raw HTTP traffic. Logrotate
keeps 14 days of Nginx and proxy logs, and auditd about nine days. This job runs every
ten minutes (scanmalware-log-archive.timer) and copies each rotated file, never a live
one, into ARCHIVE_DIR, zstd-compressed. Archives older than the retention period are
deleted.

A rotated file is renamed again by every later rotation (.1 becomes .2, and logrotate
later gzips it), so the archive name comes from the file's content: the timestamp and a
hash of its first line. The same segment therefore lands in the archive exactly once,
however often it is renamed or recompressed.

Runs as root on the host with the Debian 12 Python (3.11), stdlib only, plus the
``zstd`` command. It reads the source logs and never modifies them.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

LOG_ROOT = Path("/opt/scanmalware-mcp/logs")
AUDIT_DIR = Path("/var/log/audit")
ARCHIVE_DIR = Path("/var/log/scanmalware-mcp-archive")
RETENTION_DAYS = 365
ZSTD_LEVEL = "-10"  # ~100x on the raw HTTP log, whose tools/list bodies repeat.

# (group, directory, live file name). Only "<name>.<N>" and "<name>.<N>.gz" are archived.
SOURCES = [
    ("mcp", LOG_ROOT / "mcp", "mcp.log"),
    ("mcp", LOG_ROOT / "mcp", "mcp-full.log"),
    ("mcp", LOG_ROOT / "mcp", "mcp-http.log"),
    ("nginx", LOG_ROOT / "nginx", "access.log"),
    ("nginx", LOG_ROOT / "nginx", "error.log"),
    ("mitmproxy", LOG_ROOT / "mitmproxy", "full.log"),
    ("audit", AUDIT_DIR, "audit.log"),
]

_ROTATED = re.compile(r"^(?P<name>.+)\.(?P<n>[0-9]+)(?P<gz>\.gz)?$")
_ARCHIVED = re.compile(r"\.(?P<ts>[0-9]{8}T[0-9]{6}Z|undated)\.[0-9a-f]{16}\.zst$")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def first_line_time(line: bytes) -> dt.datetime | None:
    """Return the UTC time a log segment starts at, for the formats we keep."""
    text = line[:4096].decode("utf-8", "replace")
    utc = dt.timezone.utc
    # MCP: "2026-11-07 10:48:13,434 INFO ..." (the container logs in UTC).
    m = re.match(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", text)
    if m:
        return dt.datetime(*map(int, m.groups()), tzinfo=utc)
    # Nginx error log: "2026/11/07 11:46:37 [error] ...".
    m = re.match(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})", text)
    if m:
        return dt.datetime(*map(int, m.groups()), tzinfo=utc)
    # Nginx access log: "... [07/Nov/2026:00:04:43 +0000] ...".
    m = re.search(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\]", text)
    if m and m.group(2) in _MONTHS:
        d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
        offset = dt.timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
        local = dt.datetime(int(y), _MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                            tzinfo=dt.timezone(offset))
        return local.astimezone(utc)
    # auditd: "type=... msg=audit(1794052054.985:197321): ...".
    m = re.search(r"msg=audit\((\d{9,11})\.\d+:", text)
    # mitmproxy addon: JSON with epoch floats ("connected_at", "timestamp", ...).
    m = m or re.search(r'"(?:connected_at|timestamp_start|timestamp)": (\d{9,11})(?:\.\d+)?', text)
    if m:
        return dt.datetime.fromtimestamp(int(m.group(1)), utc)
    return None


def _open(path: Path):
    return gzip.open(path, "rb") if path.suffix == ".gz" else open(path, "rb")


def archive_name(live_name: str, first_line: bytes) -> str:
    started = first_line_time(first_line)
    stamp = started.strftime("%Y%m%dT%H%M%SZ") if started else "undated"
    digest = hashlib.sha256(first_line).hexdigest()[:16]
    return f"{live_name}.{stamp}.{digest}.zst"


def archive_file(src: Path, live_name: str, dest_dir: Path) -> Path | None:
    """Compress one rotated file into dest_dir unless that segment is already there."""
    try:
        with _open(src) as fh:
            first = fh.readline()
            if not first:
                return None  # empty segment
            target = dest_dir / archive_name(live_name, first)
            started = first_line_time(first)
            if started:
                target = dest_dir / started.strftime("%Y") / started.strftime("%m") / target.name
            if target.exists():
                return None
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(f".{target.name}.tmp")
            with open(tmp, "wb") as out:
                proc = subprocess.Popen(["zstd", "-q", ZSTD_LEVEL, "-T1", "-c"],
                                        stdin=subprocess.PIPE, stdout=out)
                assert proc.stdin is not None
                try:
                    proc.stdin.write(first)
                    shutil.copyfileobj(fh, proc.stdin, 1 << 20)
                finally:
                    proc.stdin.close()
                if proc.wait() != 0:
                    raise RuntimeError(f"zstd exited with {proc.returncode}")
    except FileNotFoundError:
        return None  # rotated away between listing and opening; the next run sees it
    except BaseException:
        if "tmp" in locals() and tmp.exists():
            tmp.unlink()
        raise
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)
    return target


def rotated_files(directory: Path, live_name: str) -> list[Path]:
    if not directory.is_dir():
        return []
    found = []
    for entry in directory.iterdir():
        m = _ROTATED.match(entry.name)
        if m and m.group("name") == live_name and entry.is_file():
            found.append(entry)
    return sorted(found, key=lambda p: int(_ROTATED.match(p.name).group("n")))


def prune(archive_dir: Path, retention_days: int, now: dt.datetime) -> list[Path]:
    """Delete archives whose segment started before the retention cut-off."""
    cutoff = now - dt.timedelta(days=retention_days)
    removed = []
    for path in archive_dir.rglob("*.zst"):
        m = _ARCHIVED.search(path.name)
        if not m:
            continue
        if m.group("ts") == "undated":
            started = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        else:
            started = dt.datetime.strptime(m.group("ts"), "%Y%m%dT%H%M%SZ").replace(
                tzinfo=dt.timezone.utc)
        if started < cutoff:
            path.unlink()
            removed.append(path)
    return removed


def run(sources, archive_dir: Path, retention_days: int, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    archive_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(archive_dir, 0o750)
    stats = {"archived": 0, "bytes_in": 0, "bytes_out": 0, "errors": 0, "pruned": 0}
    for group, directory, live_name in sources:
        for src in rotated_files(Path(directory), live_name):
            try:
                size = src.stat().st_size
                target = archive_file(src, live_name, archive_dir / group)
            except FileNotFoundError:
                continue
            except Exception as exc:  # keep going; one bad file must not stop the rest
                stats["errors"] += 1
                print(f"error archiving {src}: {exc}", file=sys.stderr)
                continue
            if target:
                stats["archived"] += 1
                stats["bytes_in"] += size
                stats["bytes_out"] += target.stat().st_size
    stats["pruned"] = len(prune(archive_dir, retention_days, now))
    usage = shutil.disk_usage(archive_dir)
    if usage.free < usage.total * 0.10:
        print(f"warning: less than 10% disk free under {archive_dir}", file=sys.stderr)
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive-dir", type=Path, default=ARCHIVE_DIR)
    parser.add_argument("--retention-days", type=int, default=RETENTION_DAYS)
    args = parser.parse_args(argv)
    if shutil.which("zstd") is None:
        print("zstd is not installed (apt-get install -y zstd)", file=sys.stderr)
        return 2
    stats = run(SOURCES, args.archive_dir, args.retention_days)
    print(" ".join(f"{k}={v}" for k, v in stats.items()))
    return 1 if stats["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
