#!/usr/bin/env python3
"""Daily security report for the ScanMalware MCP droplet.

Reads the last day of logs and prints findings, most serious first:
  HIGH    signs that an attack worked or that something is wrong with the host
  MEDIUM  attack attempts, and responses nobody should have been served
  INFO    context: restarts, deploy changes, logins, error counts

Lines carry sd-daemon priority prefixes, so under systemd the journal records HIGH
as err and MEDIUM as warning (journalctl -t scanmalware-security -p warning).
The report is also written to logs/security/report-<date>.txt.

Standard library only; runs as root on the host. See docs/OPERATIONS.md,
"Security monitoring".
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import gzip
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Any, Iterator

PRIORITY = {"HIGH": "<3>", "MEDIUM": "<4>", "INFO": "<6>"}

# Injection-style tool arguments, as seen in the October 2026 log review:
# shell commands in scan_id, file:// and metadata URLs, traversal, prompt text.
SUSPICIOUS_ARGS = re.compile(
    r"(\.\./|%2e%2e|\.\.\\|file:|gopher:|dict:|javascript:|169\.254\.|metadata\.google|"
    r"/etc/passwd|/proc/self|\.ssh/|\.aws/|\.env\b|\$\(|`|;\s*(cat|ls|id|env|sleep|curl|wget)\b|"
    r"\|\s*(sh|bash)\b|<script|\{\{|ignore (all |previous|prior)|system prompt)",
    re.I,
)
NGINX_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+) '
    r'"(?:[^"\\]|\\.)*" "(?P<ua>(?:[^"\\]|\\.)*)"(?P<rest>.*)$'
)
# Paths the site is meant to serve with a 2xx.
NGINX_EXPECTED = re.compile(r"^(/|/index\.html|/mcp|/\.well-known/[^?]*|/demo/[^?]*)(\?.*)?$")
ENTRYPOINT = "/usr/local/bin/scanmalware-mcp"


class Report:
    def __init__(self) -> None:
        self.findings: list[tuple[str, str]] = []

    def add(self, severity: str, text: str) -> None:
        self.findings.append((severity, text))

    def lines(self) -> list[tuple[str, str]]:
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        return sorted(self.findings, key=lambda item: order[item[0]])


def files_since(pattern: str, since: float) -> list[str]:
    """Current and rotated files modified after `since`, oldest first."""
    paths = [p for p in glob.glob(pattern) + glob.glob(pattern + ".*") if os.path.getmtime(p) >= since]
    return sorted(paths, key=os.path.getmtime)


def read_lines(path: str) -> Iterator[str]:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from handle


def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def mcp_events(root: str, since: float) -> Iterator[dict[str, Any]]:
    since_text = dt.datetime.fromtimestamp(since, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for path in files_since(os.path.join(root, "logs/mcp/mcp.log"), since):
        for line in read_lines(path):
            if line[:19] < since_text or " scanmalware_mcp " not in line:
                continue
            start = line.find("{")
            try:
                event = json.loads(line[start:])
            except ValueError:
                continue
            event["_ts"] = line[:19]
            yield event


def check_mcp(report: Report, root: str, since: float) -> None:
    attempts: dict[tuple[str, str], list[str]] = defaultdict(list)
    sessions = Counter()
    calls = errors = cancelled = startups = 0
    for event in mcp_events(root, since):
        name = event.get("event")
        who = (str(event.get("x_real_ip") or event.get("remote_ip")), str(event.get("user_agent") or "?")[:40])
        if name == "mcp.scan.internal_target":
            report.add(
                "HIGH",
                f"{event['_ts']} scan {event.get('scan_id')} ({event.get('tool')}) reached internal host(s) "
                f"{event.get('internal_hosts')}: url={event.get('url')} final_url={event.get('final_url')} "
                f"client={who[0]} {who[1]}",
            )
        elif name == "mcp.tool.start":
            calls += 1
            args = json.dumps(event.get("args") or {})
            match = SUSPICIOUS_ARGS.search(args)
            if match:
                attempts[who].append(f"{event.get('tool')}: ...{args[max(0, match.start() - 40):match.end() + 40]}...")
        elif name in ("mcp.tool.end", "mcp.tool.error", "mcp.tool.cancelled"):
            errors += name == "mcp.tool.error"
            cancelled += name == "mcp.tool.cancelled"
            for entry in event.get("upstream") or []:
                parts = entry.split(" ")
                if len(parts) >= 3 and parts[2].startswith("2") and re.search(r"%2F|/\.\./|/\.\.$", parts[1], re.I):
                    report.add(
                        "MEDIUM",
                        f"{event['_ts']} {event.get('tool')} got {parts[2]} for an upstream path with an encoded "
                        f"or dot segment: {parts[1]} (call {event.get('call_id')}, client {who[0]})",
                    )
        elif name == "mcp.session.start":
            sessions[str(event.get("client_name") or "?")] += 1
        elif name == "mcp.startup":
            startups += 1
    for (ip, ua), samples in sorted(attempts.items(), key=lambda kv: -len(kv[1])):
        shown = "; ".join(dict.fromkeys(samples))[:400]
        report.add("MEDIUM", f"{len(samples)} injection-style tool argument(s) from {ip} ({ua}): {shown}")
    if startups:
        report.add("INFO", f"MCP server process started {startups} time(s) (deploys or restarts)")
    top = ", ".join(f"{name} {count}" for name, count in sessions.most_common(8))
    report.add("INFO", f"{calls} tool calls, {errors} errors, {cancelled} cancelled; sessions by client: {top}")


def check_proxy(report: Report, root: str, since: float) -> None:
    # restrict_hosts.py writes a proxy.blocked line for every refusal, HTTPS
    # CONNECT included. Before that existed, only refused plain-HTTP requests
    # appeared, as http.response entries; count those too, once per flow.
    blocked = Counter()
    seen: set[str] = set()
    for path in files_since(os.path.join(root, "logs/mitmproxy/full.log"), since):
        for line in read_lines(path):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("event") == "proxy.blocked":
                when, host, port, peer = entry.get("timestamp"), entry.get("host"), entry.get("port"), entry.get("client")
            else:
                request = entry.get("request") or {}
                when, host, port = request.get("timestamp_start"), request.get("host"), request.get("port")
                peer = (entry.get("client") or {}).get("peername")
                if not host or re.fullmatch(r"(?:[a-z0-9-]+\.)*scanmalware\.com", str(host).lower().rstrip(".")):
                    continue
            if (when or 0) < since or (entry.get("id") and entry["id"] in seen):
                continue
            if entry.get("id"):
                seen.add(entry["id"])
            blocked[(host, port, (peer or ["?"])[0])] += 1
    for (host, port, peer), count in blocked.most_common():
        report.add(
            "HIGH",
            f"proxy refused {count} request(s) from {peer} to {host}:{port}; the MCP server only calls "
            f"scanmalware.com (expected only during an egress check, e.g. example.com or blocked.invalid)",
        )


def check_kernel(report: Report, since: float) -> None:
    out = run(["journalctl", "-k", "--since", f"@{int(since)}", "--no-pager", "-o", "short-iso", "-g", "scanmalware-mcp-egress-drop"])
    hits = [line for line in out.splitlines() if "scanmalware-mcp-egress-drop" in line]
    if hits:
        dsts = Counter(m.group(1) + ":" + (p.group(1) if (p := re.search(r"DPT=(\d+)", h)) else "?")
                       for h in hits if (m := re.search(r"DST=(\S+)", h)))
        report.add(
            "HIGH",
            f"firewall dropped {len(hits)} logged packet(s) from the MCP container to destinations other than "
            f"the proxy: {dict(dsts.most_common(10))}. Code in the container is trying to get out.",
        )


def check_audit(report: Report, since: float) -> None:
    if not run(["sh", "-c", "command -v ausearch"]).strip():
        report.add("INFO", "auditd is not installed; program starts and config changes are not audited")
        return
    start = dt.datetime.fromtimestamp(since).strftime("%m/%d/%Y %H:%M:%S").split(" ")
    execs = run(["ausearch", "-i", "-k", "scanmalware_mcp_exec", "--start", start[0], start[1]])
    titles = Counter(m.group(1) for m in re.finditer(r"proctitle=(.*)", execs))
    expected = sum(count for title, count in titles.items() if ENTRYPOINT in title)
    unexpected = Counter({title: count for title, count in titles.items() if ENTRYPOINT not in title})
    if unexpected:
        report.add("HIGH", f"programs started as the MCP container user (UID 10001): {dict(unexpected.most_common(10))}")
    if expected:
        report.add("INFO", f"MCP container entrypoint started {expected} time(s)")
    for key, label in (
        ("scanmalware_deploy_change", "deployment files"),
        ("scanmalware_code_change", "server code"),
        ("ssh_authorized_keys", "root's authorized_keys"),
        ("sshd_config", "SSH server config"),
        ("docker_config", "Docker config"),
    ):
        out = run(["ausearch", "-i", "-k", key, "--start", start[0], start[1]])
        names = Counter(m.group(1) for m in re.finditer(r"type=PATH .*?name=(\S+) .*?nametype=(?:CREATE|NORMAL|DELETE)", out))
        if names:
            severity = "HIGH" if key in ("ssh_authorized_keys", "sshd_config") else "INFO"
            report.add(severity, f"changes to {label}: {dict(names.most_common(8))}")


def check_ssh(report: Report, since: float, allowlist_path: str) -> None:
    out = run(["journalctl", "-u", "ssh", "--since", f"@{int(since)}", "--no-pager", "-o", "cat"])
    accepted = Counter(re.findall(r"Accepted \S+ for (\S+) from (\S+)", out))
    failed = len(re.findall(r"Invalid user|Failed \S+ for|Connection closed by authenticating", out))
    allowed: set[str] = set()
    if os.path.exists(allowlist_path):
        with open(allowlist_path, encoding="utf-8") as handle:
            allowed = {line.split("#")[0].strip() for line in handle if line.split("#")[0].strip()}

    def known(ip: str) -> bool:
        for entry in allowed:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    for (user, ip), count in accepted.most_common():
        if allowed and not known(ip):
            report.add("HIGH", f"SSH login as {user} from {ip} ({count}x), which is not in {allowlist_path}")
        else:
            report.add("INFO", f"SSH login as {user} from {ip} ({count}x)")
    if not allowed and accepted:
        report.add("INFO", f"no SSH allowlist at {allowlist_path}, so logins are listed but not judged")
    report.add("INFO", f"{failed} failed or invalid SSH attempts (password login is disabled)")


def check_nginx(report: Report, root: str, since: float) -> None:
    unexpected = Counter()
    errors = Counter()
    for path in files_since(os.path.join(root, "logs/nginx/access.log"), since):
        for line in read_lines(path):
            m = NGINX_LINE.match(line)
            if not m:
                continue
            try:
                when = dt.datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                continue
            if when < since:
                continue
            parts = m.group("req").split(" ")
            target = parts[1] if len(parts) == 3 else m.group("req")
            status = m.group("status")
            if status.startswith("2") and not NGINX_EXPECTED.match(target):
                unexpected[(target[:120], status, m.group("ip"))] += 1
            if status.startswith("5"):
                errors[status] += 1
    for (target, status, ip), count in unexpected.most_common(15):
        report.add("MEDIUM", f"nginx served {status} for unexpected path {target} to {ip} ({count}x)")
    if errors:
        report.add("INFO", f"nginx 5xx responses: {dict(errors)}")


def check_containers(report: Report, since: float) -> None:
    out = run(["docker", "inspect", "-f", "{{.Name}} {{.RestartCount}} {{.State.OOMKilled}} {{.State.StartedAt}}",
               "deploy_mcp_1", "deploy_nginx_1", "deploy_proxy_1"])
    for line in out.splitlines():
        name, restarts, oom, started = line.split(" ", 3)
        if oom == "true":
            report.add("HIGH", f"{name.lstrip('/')} was killed for running out of memory")
        try:
            started_at = dt.datetime.fromisoformat(started[:26].rstrip("Z") + "+00:00").timestamp()
        except ValueError:
            started_at = 0
        if started_at >= since:
            report.add("INFO", f"{name.lstrip('/')} (re)started at {started[:19]}Z, restart count {restarts}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hours", type=float, default=24.0, help="how far back to look (default 24)")
    parser.add_argument("--root", default="/opt/scanmalware-mcp")
    parser.add_argument("--report-dir", default=None, help="default: <root>/logs/security")
    parser.add_argument("--ssh-allowlist", default="/etc/scanmalware-mcp/ssh-allowlist")
    parser.add_argument("--keep", type=int, default=90, help="reports to keep (default 90)")
    args = parser.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    since = now.timestamp() - args.hours * 3600
    report = Report()
    for check in (
        lambda: check_mcp(report, args.root, since),
        lambda: check_proxy(report, args.root, since),
        lambda: check_kernel(report, since),
        lambda: check_audit(report, since),
        lambda: check_ssh(report, since, args.ssh_allowlist),
        lambda: check_nginx(report, args.root, since),
        lambda: check_containers(report, since),
    ):
        try:
            check()
        except Exception as exc:  # one broken source must not hide the others
            report.add("MEDIUM", f"check failed: {type(exc).__name__}: {exc}")

    lines = report.lines()
    counts = Counter(severity for severity, _ in lines)
    header = (f"ScanMalware MCP security report, {args.hours:g} h to {now:%Y-%m-%d %H:%M}Z: "
              f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['INFO']} info")
    print(f"{PRIORITY['HIGH' if counts['HIGH'] else 'INFO']}{header}")
    for severity, text in lines:
        print(f"{PRIORITY[severity]}{severity}: {text}")

    report_dir = args.report_dir or os.path.join(args.root, "logs/security")
    os.makedirs(report_dir, exist_ok=True)
    with open(os.path.join(report_dir, f"report-{now:%Y-%m-%d}.txt"), "w", encoding="utf-8") as handle:
        handle.write(header + "\n" + "".join(f"{severity}: {text}\n" for severity, text in lines))
    for old in sorted(glob.glob(os.path.join(report_dir, "report-*.txt")))[:-args.keep]:
        os.remove(old)
    return 0


if __name__ == "__main__":
    sys.exit(main())
