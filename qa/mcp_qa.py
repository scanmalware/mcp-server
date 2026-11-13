#!/usr/bin/env python3
"""Live QA sweep for the ScanMalware MCP server: call every tool, check every answer.

The unit tests in tests/ mock the ScanMalware API. This tool does the opposite: it talks
to a running server over streamable HTTP, exactly as an MCP client does, and that server
talks to the real ScanMalware API. It

  1. lints tools/list (names, titles, descriptions, argument descriptions, annotations,
     defaults that satisfy their own constraints);
  2. finds a well-populated public scan and harvests real pivot values from it (scan,
     fingerprint and segment IDs, hashes, domain, IP, ASN, JARM, favicon, CPE, ...);
  3. calls every tool with those values and checks each answer: JSON-RPC framing, isError,
     structuredContent against outputSchema, the text block mirroring structuredContent,
     limit respected, scan_id echoed, size and latency budgets, no tracebacks or internal
     details in error text;
  4. sends invalid arguments (bad UUIDs, path traversal, out-of-range limits, wrong types,
     missing or unknown arguments) and checks they fail cleanly, as tool errors;
  5. reads every resource template and checks the bytes (PNG, PEM, pcap, RSS);
  6. runs protocol checks: GET 405, Accept 406, no session ID, ping, unknown method, and
     the official SDK client on both the initialize (2025-06-18) and 2026-07-28 paths.

Targets
  --local          (default) start this checkout's server in this process, on a free
                   localhost port behind real uvicorn. Being in-process, the sweep also sees
                   which upstream API paths each call reached and with what status, so it can
                   check that rejected arguments never reached the API.
  --url URL        any deployed endpoint, e.g. https://mcp.scanmalware.com/mcp. Calls show up
                   in that server's logs with the User-Agent scanmalware-mcp-qa/<version>.

Side effects: submit_scan and submit_scan_report write to ScanMalware (a new scan; a crowd
vote on a scan). By default they get only argument-validation cases, which the server
rejects before calling the API. --allow-writes adds one real unlisted scan of
--write-target-url (example.com by default), waits for it, and casts one positive_feedback
vote on that same new scan.

Run with the locked dependencies (mcp 2.3.0), from the repository root:

    uv venv /tmp/qa-venv --python 3.14
    uv pip install --python /tmp/qa-venv/bin/python -r requirements.lock
    /tmp/qa-venv/bin/python qa/mcp_qa.py                      # local checkout
    /tmp/qa-venv/bin/python qa/mcp_qa.py --url https://mcp.scanmalware.com/mcp
    /tmp/qa-venv/bin/python qa/mcp_qa.py --only 'search_js*' -v
    /tmp/qa-venv/bin/python qa/mcp_qa.py --probe get_scan_summary '{"scan_id": "..."}'

Exit status: 0 when nothing failed (warnings allowed), 1 when any check failed, 2 on a
harness error (target unreachable, bad options).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fnmatch
import json
import os
import re
import socket
import sys
import time
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
QA_VERSION = "1.0"
USER_AGENT = f"scanmalware-mcp-qa/{QA_VERSION}"
CLIENT_INFO = {"name": "scanmalware-mcp-qa", "version": QA_VERSION}
HANDSHAKE_PROTOCOL = "2025-06-18"
MODERN_PROTOCOL = "2026-07-28"
ACCEPT_BOTH = "application/json, text/event-stream"

# Environment that changes what a local server does; the QA run wants the public defaults.
_LOCAL_ENV_CLEARED = (
    "SCANMALWARE_BEARER_TOKEN",
    "SCANMALWARE_PROXY_URL",
    "SCANMALWARE_CA_CERT",
    "SCANMALWARE_ALLOW_PRIVATE_TARGETS",
    "SCANMALWARE_ALLOW_HTTP",
    "SCANMALWARE_LOG_FILE",
    "SCANMALWARE_FULL_LOG_FILE",
    "MCP_AUTH_TOKEN",
    "MCP_HTTP_LOG_FILE",
)


# --------------------------------------------------------------------------------------
# JSON-RPC over streamable HTTP
# --------------------------------------------------------------------------------------


@dataclass
class RpcReply:
    """One POST to the MCP endpoint and what came back."""

    request_id: int | None
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    message: dict[str, Any] | None = None  # the JSON-RPC response matching request_id
    others: list[dict[str, Any]] = field(default_factory=list)  # notifications etc. in the same stream
    body_bytes: int = 0
    elapsed_s: float = 0.0
    transport_error: str | None = None
    body_text: str = ""

    @property
    def result(self) -> dict[str, Any] | None:
        if self.message is None:
            return None
        result = self.message.get("result")
        return result if isinstance(result, dict) else None

    @property
    def error(self) -> dict[str, Any] | None:
        if self.message is None:
            return None
        error = self.message.get("error")
        return error if isinstance(error, dict) else None


def _parse_sse(text: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    data_lines: list[str] = []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
        elif line == "" and data_lines:
            try:
                parsed = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                parsed = {"__unparsed__": "\n".join(data_lines)[:500]}
            if isinstance(parsed, dict):
                messages.append(parsed)
            data_lines = []
    return messages


class McpHttp:
    """A deliberately thin client: every byte of every reply stays visible to the checks."""

    def __init__(self, url: str, http: httpx.AsyncClient, *, call_timeout_s: float) -> None:
        self.url = url
        self.http = http
        self.call_timeout_s = call_timeout_s
        self.protocol_version = HANDSHAKE_PROTOCOL
        self._next_id = 0
        self.server_info: dict[str, Any] = {}
        self.init_result: dict[str, Any] = {}

    def new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"accept": ACCEPT_BOTH, "content-type": "application/json", "mcp-protocol-version": self.protocol_version}
        if extra:
            headers.update(extra)
        return headers

    async def post(
        self,
        payload: dict[str, Any] | bytes,
        *,
        headers: dict[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> RpcReply:
        request_id = payload.get("id") if isinstance(payload, dict) else None
        reply = RpcReply(request_id=request_id)
        started = time.perf_counter()
        try:
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            response = await self.http.post(
                self.url,
                content=body,
                headers=self._headers(headers),
                timeout=timeout_s or self.call_timeout_s,
            )
        except httpx.HTTPError as exc:
            reply.transport_error = f"{type(exc).__name__}: {exc}"
            reply.elapsed_s = time.perf_counter() - started
            return reply
        reply.elapsed_s = time.perf_counter() - started
        reply.http_status = response.status_code
        reply.headers = {k.lower(): v for k, v in response.headers.items()}
        reply.body_bytes = len(response.content)
        text = response.text
        reply.body_text = text[:2000]
        content_type = reply.headers.get("content-type", "")
        messages: list[dict[str, Any]] = []
        if content_type.startswith("text/event-stream"):
            messages = _parse_sse(text)
        elif text.strip():
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                messages = [parsed]
            elif isinstance(parsed, list):
                messages = [m for m in parsed if isinstance(m, dict)]
        for message in messages:
            if request_id is not None and message.get("id") == request_id and ("result" in message or "error" in message):
                reply.message = message
            else:
                reply.others.append(message)
        return reply

    async def request(self, method: str, params: dict[str, Any] | None = None, *, timeout_s: float | None = None) -> RpcReply:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self.new_id(), "method": method}
        if params is not None:
            payload["params"] = params
        return await self.post(payload, timeout_s=timeout_s)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> RpcReply:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        return await self.post(payload)

    async def initialize(self) -> RpcReply:
        reply = await self.request(
            "initialize",
            {"protocolVersion": HANDSHAKE_PROTOCOL, "capabilities": {}, "clientInfo": CLIENT_INFO},
            timeout_s=30,
        )
        if reply.result is None:
            raise HarnessError(f"initialize failed: {_describe_reply(reply)}")
        self.init_result = reply.result
        self.protocol_version = str(reply.result.get("protocolVersion") or HANDSHAKE_PROTOCOL)
        self.server_info = reply.result.get("serverInfo") or {}
        await self.notify("notifications/initialized")
        return reply

    async def list_tools(self) -> tuple[list[dict[str, Any]], list[RpcReply]]:
        tools: list[dict[str, Any]] = []
        replies: list[RpcReply] = []
        cursor: str | None = None
        for _ in range(50):
            reply = await self.request("tools/list", {"cursor": cursor} if cursor else {}, timeout_s=30)
            replies.append(reply)
            if reply.result is None:
                raise HarnessError(f"tools/list failed: {_describe_reply(reply)}")
            tools.extend(reply.result.get("tools") or [])
            cursor = reply.result.get("nextCursor")
            if not cursor:
                break
        return tools, replies

    async def call_tool(self, name: str, arguments: Any, *, timeout_s: float | None = None) -> RpcReply:
        return await self.request("tools/call", {"name": name, "arguments": arguments}, timeout_s=timeout_s)


class HarnessError(RuntimeError):
    """The sweep itself cannot continue (target down, handshake broken)."""


def _describe_reply(reply: RpcReply) -> str:
    if reply.transport_error:
        return reply.transport_error
    if reply.error:
        return f"JSON-RPC error {reply.error.get('code')}: {str(reply.error.get('message'))[:300]}"
    if reply.message is None:
        return f"HTTP {reply.http_status}, no JSON-RPC response for id {reply.request_id}: {reply.body_text[:300]!r}"
    return f"HTTP {reply.http_status}"


# --------------------------------------------------------------------------------------
# Local in-process target
# --------------------------------------------------------------------------------------


class UpstreamTap:
    """Collects the server's own end-of-call log events, keyed by JSON-RPC request id.

    Each mcp.tool.end / mcp.tool.error event lists the upstream requests the call made
    ("GET /api/v1/... 200"), so a case can check where its arguments actually went.
    """

    EVENTS = {"mcp.tool.end", "mcp.tool.error", "mcp.resource.end", "mcp.resource.error"}

    def __init__(self) -> None:
        self.by_request: dict[str, dict[str, Any]] = {}
        self.waiters: dict[str, asyncio.Event] = {}

    def log_event(self, level: int, event: str, **fields: Any) -> None:
        if event not in self.EVENTS:
            return
        key = str(fields.get("request_id"))
        self.by_request[key] = {"event": event, **fields}
        waiter = self.waiters.get(key)
        if waiter is not None:
            waiter.set()

    async def get(self, request_id: int | None, *, wait_s: float = 2.0) -> dict[str, Any] | None:
        key = str(request_id)
        if key in self.by_request:
            return self.by_request[key]
        event = self.waiters.setdefault(key, asyncio.Event())
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(event.wait(), wait_s)
        self.waiters.pop(key, None)
        return self.by_request.get(key)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LocalServer:
    """This checkout's server, in this process, behind uvicorn on 127.0.0.1."""

    def __init__(self) -> None:
        self.tap = UpstreamTap()
        self.url = ""
        self._uvicorn: Any = None
        self._task: asyncio.Task[None] | None = None
        self._module: Any = None
        self._saved_env: dict[str, str] = {}
        self._saved_attrs: list[tuple[Any, str, Any]] = []

    async def __aenter__(self) -> "LocalServer":
        import logging

        import uvicorn

        sys.path.insert(0, str(REPO_ROOT))
        from scanmalware_mcp import server as module  # noqa: PLC0415 - import after sys.path

        self._module = module
        for name in _LOCAL_ENV_CLEARED:
            if name in os.environ:
                self._saved_env[name] = os.environ.pop(name)
        # No log files in the checkout; the tap still sees every event.
        for attr, replacement in (("_configure_logging", lambda: None), ("_log_event", self.tap.log_event)):
            self._saved_attrs.append((module, attr, getattr(module, attr)))
            setattr(module, attr, replacement)
        logging.getLogger("scanmalware_mcp").setLevel(logging.CRITICAL)
        logging.getLogger("mcp").setLevel(logging.ERROR)
        for noisy in ("httpx", "httpx2", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
        port = _free_port()
        server = module.create_server(host="127.0.0.1", port=port)
        app = server.streamable_http_app()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on", access_log=False)
        self._uvicorn = uvicorn.Server(config)
        self._task = asyncio.create_task(self._uvicorn.serve())
        deadline = time.monotonic() + 15
        while not self._uvicorn.started:
            if self._task.done():
                self._task.result()
                raise HarnessError("local server exited during startup")
            if time.monotonic() > deadline:
                raise HarnessError("local server did not start within 15 s")
            await asyncio.sleep(0.05)
        self.url = f"http://127.0.0.1:{port}/mcp"
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
        if self._task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._task, 10)
        module = self._module
        if module is not None and getattr(module, "_SHARED_CLIENT", None) is not None:
            with contextlib.suppress(Exception):
                await module._SHARED_CLIENT.aclose()
            module._SHARED_CLIENT = None
            module._SHARED_CLIENT_LOCK = None
        for obj, attr, value in reversed(self._saved_attrs):
            setattr(obj, attr, value)
        os.environ.update(self._saved_env)


# --------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
_RANK = {PASS: 0, SKIP: 1, WARN: 2, FAIL: 3}


@dataclass
class Issue:
    level: str
    check: str
    detail: str


@dataclass
class Result:
    section: str
    subject: str  # tool name, resource URI or protocol probe
    label: str
    args: Any = None
    status: str = PASS
    issues: list[Issue] = field(default_factory=list)
    elapsed_s: float | None = None
    body_bytes: int | None = None
    upstream: list[str] | None = None
    note: str = ""
    sample: str = ""

    def add(self, level: str, check: str, detail: str) -> None:
        self.issues.append(Issue(level, check, detail))
        if _RANK[level] > _RANK[self.status]:
            self.status = level

    def to_json(self) -> dict[str, Any]:
        return {
            "section": self.section,
            "subject": self.subject,
            "label": self.label,
            "status": self.status,
            "args": self.args,
            "issues": [issue.__dict__ for issue in self.issues],
            "elapsed_s": None if self.elapsed_s is None else round(self.elapsed_s, 3),
            "body_bytes": self.body_bytes,
            "upstream": self.upstream,
            "note": self.note,
            "sample": self.sample,
        }


# --------------------------------------------------------------------------------------
# Seed values: real pivots harvested from live data, so every tool gets a meaningful input
# --------------------------------------------------------------------------------------


class MissingSeed(KeyError):
    pass


class Seeds:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.sources: dict[str, str] = {}

    def set(self, key: str, value: Any, source: str, *, overwrite: bool = False) -> None:
        if value is None or value == "" or value == []:
            return
        if key in self.values and not overwrite:
            return
        self.values[key] = value
        self.sources[key] = source

    def get(self, key: str) -> Any:
        if key not in self.values:
            raise MissingSeed(key)
        return self.values[key]

    def __contains__(self, key: str) -> bool:
        return key in self.values


_PLACEHOLDER = re.compile(r"\$([a-z_][a-z0-9_]*)")


def resolve(value: Any, seeds: Seeds) -> Any:
    """Fill "$key" placeholders from the seeds. A bare "$key" keeps the seed's own type."""
    if callable(value):
        return value(seeds)
    if isinstance(value, str):
        whole = _PLACEHOLDER.fullmatch(value)
        if whole:
            return seeds.get(whole.group(1))
        return _PLACEHOLDER.sub(lambda m: str(seeds.get(m.group(1))), value)
    if isinstance(value, list):
        return [resolve(item, seeds) for item in value]
    if isinstance(value, dict):
        return {key: resolve(item, seeds) for key, item in value.items()}
    return value


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _first(value: Any, *keys: str) -> Any:
    """First non-empty value stored under any of these keys, anywhere in the document."""
    wanted = set(keys)
    for key, item in _walk(value):
        if key in wanted and item not in (None, "", [], {}):
            return item
    return None


def _host(url: str | None) -> str | None:
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    return httpx.URL(url).host or None


# --------------------------------------------------------------------------------------
# The plan: what each tool is called with, and what its answer must look like
# --------------------------------------------------------------------------------------

Check = Callable[[dict[str, Any], dict[str, Any], Seeds], list[tuple[str, str, str]]]


@dataclass
class Case:
    tool: str
    args: Any = field(default_factory=dict)
    label: str = "basic"
    # ok: must succeed. reject: must fail as a tool or params error, before any upstream
    # call. should_reject: the same, but accepting it is a warning. probe: record only.
    # traversal: a free-text value that must stay inside its own URL path segment.
    expect: str = "ok"
    finds: str | None = None  # seed whose value should appear in the answer (a pivot that finds its origin)
    nonempty: bool = False  # the answer should hold at least one row
    names_arg: str | None = None  # a rejection message should name this argument
    check: Check | None = None
    timeout_s: float | None = None
    write: bool = False
    limit_rows: bool = True  # False where limit caps something other than the main list


def _rows(data: Any) -> tuple[str | None, list[Any] | None]:
    """The answer's main list: a known row key, else its longest top-level list."""
    if isinstance(data, list):
        return None, data
    if not isinstance(data, dict):
        return None, None
    for key in ("results", "items", "scans", "matches", "fingerprints", "segments", "scripts", "records",
                "domains", "hosts", "certificates", "signatures", "technologies", "alerts", "threats",
                "result", "data", "rows", "entries", "events", "history"):
        value = data.get(key)
        if isinstance(value, list):
            return key, value
    lists = [(key, value) for key, value in data.items() if isinstance(value, list)]
    if not lists:
        for key in ("data", "result", "pagination"):
            if isinstance(data.get(key), dict):
                return _rows(data[key])
        return None, None
    return max(lists, key=lambda kv: len(kv[1]))


def _check_keys(*keys: str) -> Check:
    def check(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
        missing = [key for key in keys if key not in data]
        return [(FAIL, "shape", f"missing top-level keys {missing}")] if missing else []

    return check


def _check_row_keys(*keys: str) -> Check:
    def check(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
        _, rows = _rows(data)
        bad = [i for i, row in enumerate(rows or []) if not isinstance(row, dict) or any(k not in row for k in keys)]
        return [(FAIL, "shape", f"rows {bad[:5]} lack one of {list(keys)}")] if bad else []

    return check


def _check_status_completed(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    status = data.get("status") or _first(data, "status")
    if status != "completed":
        return [(FAIL, "shape", f"status is {status!r} for a scan that completed")]
    return []


def _check_wait(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    issues = _check_status_completed(data, args, seeds)
    if data.get("timeout"):
        issues.append((FAIL, "shape", "timeout is true for a scan that had already completed"))
    return issues


def _check_counts(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    counts = data.get("counts")
    queries = args.get("queries") or []
    if not isinstance(counts, dict):
        return [(FAIL, "shape", f"counts is {type(counts).__name__}, expected an object keyed by query")]
    missing = [query for query in queries if query not in counts]
    if missing:
        return [(FAIL, "shape", f"no count for {missing}")]
    return []


def _check_hosts_per_source(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    # limit caps hosts per evidence kind; the de-duplicated union in "hosts" may be longer.
    limit = args.get("limit")
    over = {kind: len(hosts) for kind, hosts in (data.get("sources") or {}).items()
            if isinstance(hosts, list) and isinstance(limit, int) and len(hosts) > limit}
    return [(FAIL, "limit", f"limit={limit} per evidence kind, but {over}")] if over else []


def _check_fingerprint_id(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    got = data.get("id", data.get("fingerprint_id"))
    if got is not None and int(got) != int(args["fingerprint_id"]):
        return [(FAIL, "id-echo", f"asked for fingerprint {args['fingerprint_id']}, got {got}")]
    return []


def _check_new_scan(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    scan_id = data.get("scan_id") or data.get("id")
    try:
        uuid.UUID(str(scan_id))
    except ValueError:
        return [(FAIL, "shape", f"no scan_id UUID in the submission answer: {str(data)[:200]}")]
    return []


def _check_compacted(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    issues = _check_status_completed(data, args, seeds)
    if not isinstance(data.get("compacted"), list):
        issues.append((FAIL, "shape", "compact result has no compacted list naming what was left out"))
    elif "network_data" in data and isinstance(data["network_data"], dict) and "http_transactions" in data["network_data"]:
        issues.append((FAIL, "shape", "compact result still carries network_data.http_transactions"))
    return issues


def _check_fingerprint_page(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    rows = data.get("fingerprints") or []
    issues = []
    if data.get("fingerprints_count") != len(rows):
        issues.append((FAIL, "shape", f"fingerprints_count {data.get('fingerprints_count')} but {len(rows)} rows"))
    total = data.get("total_scripts")
    if isinstance(total, int) and total < len(rows) + args.get("offset", 0):
        issues.append((FAIL, "shape", f"total_scripts {total} is below offset + rows"))
    return issues


def _check_versions_limit(data: dict[str, Any], args: dict[str, Any], seeds: Seeds) -> list[tuple[str, str, str]]:
    cap = args.get("versions_limit")
    over = [row.get("name") for row in data.get("top_libraries") or []
            if isinstance(row, dict) and isinstance(row.get("versions"), dict) and len(row["versions"]) > cap]
    issues = [(FAIL, "limit", f"versions_limit={cap} but these list more: {over[:5]}")] if over else []
    if not isinstance(data.get("total_libraries"), int):
        issues.append((FAIL, "shape", "no total_libraries"))
    return issues


def _yesterday(_: Seeds) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))


def build_plan() -> list[Case]:
    """One or more cases for every tool. Placeholders ($name) come from the seeds."""
    s = "$scan_id"
    plan = [
        # Scans
        Case("get_recent_scans", {"limit": 3}, check=_check_row_keys("scan_id", "url", "status"), nonempty=True),
        Case("get_recent_scans", {"page": 2, "limit": 3}, label="page 2", nonempty=True),
        Case("submit_scan", {"url": "$write_url", "scan_type": "unlisted"}, write=True, check=_check_new_scan),
        Case("get_scan_summary", {"scan_id": s}, check=_check_status_completed),
        Case("wait_for_scan", {"scan_id": s, "timeout_s": 30, "poll_interval_s": 1}, check=_check_wait),
        Case("get_scan_result", {"scan_id": s}, check=_check_compacted),
        Case("get_scan_result", {"scan_id": s, "compact": False}, label="full", check=_check_status_completed),
        Case("get_scan_progress", {"scan_id": s}),
        Case("get_scan_pivot_values", {"scan_id": s}, check=_check_keys("scan_id", "resources", "scripts")),
        Case("get_scan_graph", {"scan_ids": [s, "$scan_id_2"]}, finds="scan_id"),
        Case("get_scan_reports", {"scan_id": s}),
        Case("get_scan_ioc", {"scan_id": s}),
        Case("get_scan_dns", {"scan_id": s}),
        Case("search_scans", {"q": "$domain", "limit": 3}, nonempty=True),
        Case("search_similar_scans", {"scan_id": s, "limit": 3}),
        Case("search_semantic", {"query": "bank login page asking for card details", "limit": 3}, nonempty=True),
        # SMQL
        Case("get_smql_filters", {}, check=_check_keys("syntax", "categories")),
        Case("search_smql", {"q": "domain:$domain", "limit": 3}, finds="scan_id", nonempty=True),
        Case("search_smql", {"q": "domain:$domain", "count_only": True}, label="count_only"),
        Case("get_smql_facets", {"q": "domain:$domain", "size": 3, "sample": 100}),
        Case("search_smql_domains", {"q": "ct_ip:$ip", "limit": 3}),
        Case("count_smql_queries", {"queries": ["domain:$domain", "title:login"]}, check=_check_counts),
        # Per-scan analysis modules
        Case("get_ai_analysis", {"scan_id": s}),
        Case("get_tls_details", {"scan_id": s}),
        Case("get_tls_asn1", {"scan_id": s}),
        Case("get_technologies_by_scan", {"scan_id": s}),
        Case("get_bot_protection", {"scan_id": s}),
        Case("get_yara_matches", {"scan_id": s}),
        Case("get_yara_by_scan", {"scan_id": s}),
        Case("get_jarm_signatures", {"scan_id": s}),
        Case("get_analyzer_results", {"scan_id": s}),
        Case("get_clipboard_events", {"scan_id": s}),
        Case("get_pastejacking", {"scan_id": s}),
        Case("get_favicon", {"scan_id": s}),
        Case("get_cpe_by_scan", {"scan_id": s}),
        Case("get_ids_alerts", {"scan_id": s}),
        Case("get_malware_by_scan", {"scan_id": s}),
        Case("get_safe_browsing", {"scan_id": s}),
        Case("get_rdap", {"scan_id": s}),
        Case("get_ocr_by_scan", {"scan_id": s}),
        Case("get_open_graph", {"scan_id": s}),
        Case("get_netlog", {"scan_id": s}),
        Case("get_pcap_metadata", {"scan_id": s}),
        Case("get_js_runtime_behaviour", {"scan_id": s}),
        Case("search_js_runtime_similar", {"scan_id": "$runtime_scan_id", "limit": 3}),
        # Domains, IPs, DNS, CT
        Case("get_domain_scans", {"domain": "$domain", "limit": 3}, nonempty=True),
        Case("get_domain_history", {"domain": "$domain", "limit": 3}, nonempty=True),
        Case("get_domain_stats", {"domain": "$domain"}),
        Case("get_domain_hosts", {"domain": "$domain", "limit": 3, "max_scans": 20}, limit_rows=False,
             check=_check_hosts_per_source),
        Case("search_by_ip", {"ip_address": "$ip", "limit": 3}, nonempty=True),
        Case("get_ip_stats", {"ip_address": "$ip", "limit": 3}),
        Case("search_by_asn", {"asn_number": "$asn", "limit": 3}, nonempty=True),
        Case("search_by_nameserver", {"nameserver": "$nameserver"}),
        Case("search_by_registrar", {"registrar_name": "$registrar", "limit": 3}, nonempty=True),
        Case("get_dns_history", {"name": "$host", "limit": 3}),
        Case("search_reverse_dns", {"kind": "ip", "value": "$ip", "limit": 3}),
        Case("search_reverse_dns", {"kind": "ns", "value": "$nameserver", "limit": 3}, label="kind=ns"),
        Case("get_ct_certificates", {"domain": "$domain"}),
        Case("get_ct_dns_records", {"domain": "$domain"}),
        Case("get_ct_domains_by_ip", {"ip_address": "$ip"}),
        Case("get_ct_root_domains_by_ip", {"ip_address": "$ip", "limit": 3}),
        Case("get_ct_similar_domains", {"domain": "$domain"}),
        Case("get_ct_timeline", {"domain": "$domain"}),
        # Hash pivots taken from the seed scan
        Case("search_by_jarm", {"jarm_signature": "$jarm", "limit": 3}, nonempty=True),
        Case("search_by_favicon", {"hash_value": "$favicon_md5", "hash_type": "md5", "limit": 3}, nonempty=True),
        # The MD5 a model is most likely to use: the one get_favicon itself reports.
        Case("search_by_favicon", {"hash_value": "$favicon_md5_served", "hash_type": "md5", "limit": 3},
             label="md5 from get_favicon", nonempty=True),
        Case("search_by_favicon", {"hash_value": "$favicon_mmh3_text", "limit": 3}, label="mmh3", nonempty=True),
        Case("search_favicon_mmh3", {"mmh3_hash": "$favicon_mmh3", "limit": 3}, nonempty=True),
        Case("search_by_fuzzy_hash", {"hash_type": "tlsh", "hash_value": "$tlsh", "limit": 3}, finds="scan_id"),
        Case("search_by_screenshot_hash", {"hash_type": "phash", "hash_value": "$phash_hex", "limit": 3},
             finds="scan_id"),
        Case("search_similar_screenshots", {"hash_value": "$phash_int", "limit": 3}, nonempty=True),
        Case("search_cpe", {"cpe_pattern": "$cpe_pattern", "limit": 3}, nonempty=True),
        Case("search_tracking_key", {"tracker_type": "$tracker_type", "key": "$tracker_key", "limit": 3},
             nonempty=True),
        Case("search_js_runtime_by_composite_hash", {"composite_hash": "$runtime_composite", "limit": 3},
             finds="runtime_scan_id"),
        Case("search_js_runtime_by_signature", {"signature": "$runtime_signature", "limit": 3}),
        # Threat feeds and AI
        Case("search_ai_high_risk", {"limit": 3}, nonempty=True),
        Case("search_ai_scam_type", {"scam_type": "$scam_type", "limit": 3}, nonempty=True),
        Case("search_ai_classification", {"classification": "CONFIRMED_SCAM", "limit": 3}, nonempty=True),
        Case("search_analyzer_high_risk", {"limit": 3}),
        Case("get_recent_threats", {"limit": 3}),
        Case("get_recent_yara_threats", {"limit": 3}),
        Case("search_suspicious_clipboard", {"limit": 3}),
        Case("search_ocr", {"q": "password", "limit": 3}, nonempty=True),
        Case("search_ocr_pattern", {"pattern": "verify your account", "limit": 3}),
        # Platform statistics
        Case("get_api_root", {}),
        Case("get_health", {}),
        Case("get_platform_stats", {}),
        Case("get_latest_capabilities", {}),
        Case("get_capabilities_by_date", {"scan_date": _yesterday}),
        Case("get_analyzer_stats", {}),
        Case("get_favicon_stats", {}),
        Case("get_screenshot_stats", {}),
        Case("get_clipboard_stats", {}),
        Case("get_cpe_stats", {}),
        Case("get_jarm_stats", {}),
        Case("get_malware_stats", {}),
        Case("get_yara_stats", {}),
        Case("get_safe_browsing_stats", {}),
        Case("get_ocr_stats", {}),
        Case("get_top_tracking_keys", {"limit": 3}, nonempty=True),
        # Technologies
        Case("search_technologies", {"q": "WordPress", "limit": 3}, nonempty=True),
        Case("get_technology_combinations", {"tech_name": "$tech_name", "limit": 3}),
        Case("get_popular_technologies", {"limit": 3}, nonempty=True),
        Case("get_technology_stats", {}),
        # JavaScript runtime and segments
        Case("get_js_runtime_stats", {}),
        Case("get_js_runtime_health", {}),
        Case("get_js_runtime_coverage", {}),
        Case("search_js_obfuscation", {"limit": 3}),
        Case("search_js_malware_families", {"limit": 3}),
        Case("get_js_segments_by_scan", {"scan_id": "$segment_scan_id", "limit": 3}, nonempty=True),
        Case("search_js_segments_by_hash", {"code_hash": "$segment_code_hash", "limit": 3}, nonempty=True),
        Case("search_js_segments_by_normalized_hash", {"normalized_hash": "$segment_normalized_hash", "limit": 3},
             nonempty=True),
        Case("get_js_segments_suspicious", {"scan_id": "$segment_scan_id", "limit": 3}),
        Case("get_js_segments_unknown", {"scan_id": "$segment_scan_id", "limit": 3}),
        Case("run_js_differential_analysis", {"scan_id": "$fp_scan_id"}),
        # JavaScript fingerprints, from a script that is known to exist
        Case("get_js_fingerprints", {"scan_id": "$fp_scan_id", "limit": 3}, nonempty=True, check=_check_fingerprint_page),
        Case("get_js_fingerprints", {"scan_id": "$fp_scan_id", "limit": 2, "offset": 1}, label="offset=1",
             check=_check_fingerprint_page),
        Case("get_js_library_inventory", {"library": "$js_library"}),
        Case("search_js_fingerprint_patterns", {"has_eval": True, "limit": 3}),
        Case("search_js_fingerprint_obfuscated", {"per_page": 3}, nonempty=True),
        Case("search_js_fingerprint_by_server", {"server_type": "nginx", "limit": 3}),
        Case("search_js_fingerprint_by_bundler", {"bundler_type": "webpack", "per_page": 3}),
        Case("search_js_fingerprint_by_cdn", {"cdn_type": "cloudflare", "limit": 3}),
        Case("search_js_fingerprint_by_library", {"library_name": "$js_library", "per_page": 3}, nonempty=True),
        Case("search_js_fingerprint_by_library_version",
             {"library": "$js_library", "version": "$js_library_version", "limit": 3}, nonempty=True),
        Case("search_js_fingerprint_by_fuzzy_hash", {"fuzzy_hash": "$fp_fuzzy", "limit": 3}),
        Case("search_js_fingerprint_by_md5", {"hash_value": "$fp_md5", "limit": 3}, nonempty=True),
        Case("search_js_fingerprint_by_normalized_hash", {"hash_value": "$fp_normalized", "limit": 3}, nonempty=True),
        Case("search_js_fingerprint_by_sha1", {"hash_value": "$fp_sha1", "limit": 3}, nonempty=True),
        Case("search_js_fingerprint_by_sha256", {"hash_value": "$fp_sha256", "limit": 3}, nonempty=True),
        Case("find_js_fingerprint_similar_by_hash", {"content_sha256": "$fp_sha256", "limit": 3}),
        Case("search_jsfingerprints_by_bundler", {"bundler": "webpack", "limit": 3}),
        Case("search_jsfingerprints_by_library", {"library": "$js_library", "limit": 3}, nonempty=True),
        Case("search_jsfingerprints_by_library_version",
             {"library": "$js_library", "version": "$js_library_version", "limit": 3}, nonempty=True),
        Case("search_jsfingerprints_by_fuzzy_hash", {"fuzzy_hash": "$fp_fuzzy", "limit": 3}),
        Case("search_jsfingerprints_by_md5", {"hash_value": "$fp_md5", "limit": 3}, nonempty=True),
        Case("search_jsfingerprints_by_normalized_hash", {"hash_value": "$fp_normalized", "limit": 3}, nonempty=True),
        Case("search_jsfingerprints_by_sha1", {"hash_value": "$fp_sha1", "limit": 3}, nonempty=True),
        Case("search_jsfingerprints_by_sha256", {"hash_value": "$fp_sha256", "limit": 3}, nonempty=True),
        Case("get_jsfingerprint", {"fingerprint_id": "$fp_id"}, check=_check_fingerprint_id),
        Case("get_jsfingerprint_similar", {"fingerprint_id": "$fp_id", "limit": 3}),
        Case("get_jsfingerprint_similarity_counts", {"fingerprint_id": "$fp_id"}),
        Case("get_jsfingerprint_source", {"fingerprint_id": "$fp_id"}),
        Case("get_jsfingerprint_hash_prevalence", {"scan_id": "$fp_scan_id"}),
        Case("get_jsfingerprint_bundle_stats", {}),
        Case("get_jsfingerprint_library_stats", {}),
        Case("get_jsfingerprint_library_stats", {"limit": 5, "versions_limit": 3}, label="limit=5 versions_limit=3",
             check=_check_versions_limit),
        # Deobfuscation, from a script the deobfuscator rated heavily obfuscated
        Case("get_scan_deobfuscation", {"scan_id": "$obf_scan_id"}),
        Case("get_script_deobfuscation", {"fingerprint_id": "$obf_fp_id"}),
        Case("get_script_decoded_source", {"fingerprint_id": "$obf_fp_id"}),
        Case("get_script_command_literals", {"fingerprint_id": "$obf_fp_id"}),
        Case("get_file_analysis", {"sha256": "$file_sha256"}),
        # Writes (only with --allow-writes), against the scan this run submitted
        Case("wait_for_scan", {"scan_id": "$new_scan_id", "timeout_s": 240, "poll_interval_s": 3},
             label="new scan", write=True, timeout_s=300),
        Case("submit_scan_report",
             {"scan_id": "$new_scan_id", "report_type": "positive_feedback",
              "report_details": "Automated QA run of the ScanMalware MCP server (scanmalware-mcp-qa)."},
             write=True),
    ]
    return plan


# Invalid input. Each must be refused by the server itself, as a tool error naming the
# argument, with no upstream request. "should_reject" marks checks the server is not
# documented to make; accepting those is a warning, not a failure.
_BAD_UUIDS = [("not-a-uuid", "reject"), ("../recent", "reject")]
_RANDOM_UUID = "00000000-0000-4000-8000-000000000000"


def build_invalid_cases(tools: dict[str, dict[str, Any]], *, sample: bool) -> list[Case]:
    cases: list[Case] = []
    seen_kind: set[str] = set()

    def add(case: Case, kind: str) -> None:
        if sample and kind in seen_kind:
            return
        seen_kind.add(kind)
        cases.append(case)

    for name, tool in sorted(tools.items()):
        schema = tool.get("inputSchema") or {}
        props: dict[str, Any] = schema.get("properties") or {}
        required: list[str] = schema.get("required") or []
        base = _minimal_valid_args(name, props, required)
        if required:
            add(Case(name, {}, label="no arguments", expect="reject", names_arg=required[0]), "missing")
        for arg in required:
            wrong = _wrong_type_value(props.get(arg) or {})
            if wrong is not None:
                add(Case(name, {**base, arg: wrong}, label=f"{arg} wrong type", expect="reject", names_arg=arg),
                    f"type:{_json_type(props.get(arg) or {})}")
        if "scan_id" in props:
            for value, expect in _BAD_UUIDS:
                add(Case(name, {**base, "scan_id": value}, label=f"scan_id={value}", expect=expect,
                         names_arg="scan_id"), f"scan_id:{value}")
        if "fingerprint_id" in props:
            # An integer in the path cannot traverse, so reaching the API with it is untidy, not unsafe.
            add(Case(name, {**base, "fingerprint_id": 0}, label="fingerprint_id=0", expect="should_reject",
                     names_arg="fingerprint_id"), "fingerprint_id")
        for arg, spec in props.items():
            enum = _enum_of(spec)
            if enum:
                add(Case(name, {**base, arg: "qa-not-an-option"}, label=f"{arg} not in enum", expect="reject",
                         names_arg=arg), "enum")
        if "limit" in props:
            add(Case(name, {**base, "limit": 0}, label="limit=0", expect="should_reject", names_arg="limit"),
                "limit")
        if "per_page" in props:
            add(Case(name, {**base, "per_page": 0}, label="per_page=0", expect="should_reject",
                     names_arg="per_page"), "per_page")
        if "page" in props:
            add(Case(name, {**base, "page": 0}, label="page=0", expect="should_reject", names_arg="page"), "page")
        if "offset" in props:
            add(Case(name, {**base, "offset": -1}, label="offset=-1", expect="should_reject", names_arg="offset"),
                "offset")

    specific = [
        Case("submit_scan", {"url": "http://127.0.0.1/", "scan_type": "unlisted"}, label="loopback target",
             expect="reject", names_arg="private"),
        Case("submit_scan", {"url": "http://10.0.0.5/admin", "scan_type": "unlisted"}, label="RFC 1918 target",
             expect="reject", names_arg="private"),
        Case("submit_scan", {"url": "http://[::1]:8080/", "scan_type": "unlisted"}, label="IPv6 loopback",
             expect="reject", names_arg="private"),
        Case("submit_scan", {"url": "file:///etc/passwd", "scan_type": "unlisted"}, label="file: URL",
             expect="reject", names_arg="http"),
        Case("submit_scan", {"url": "javascript:alert(1)", "scan_type": "unlisted"}, label="javascript: URL",
             expect="reject", names_arg="http"),
        Case("submit_scan", {"url": "https://example.com/"}, label="no scan_type", expect="reject",
             names_arg="scan_type"),
        Case("submit_scan_report", {"scan_id": _RANDOM_UUID, "report_type": "phishing"},
             label="captcha-only report type", expect="reject", names_arg="report_type"),
        Case("submit_scan_report", {"scan_id": _RANDOM_UUID, "report_type": "positive_feedback",
                                    "report_details": "x" * 1001}, label="report_details > 1000",
             expect="reject", names_arg="report_details"),
        Case("wait_for_scan", {"scan_id": _RANDOM_UUID, "timeout_s": 0}, label="timeout_s=0", expect="reject",
             names_arg="timeout_s"),
        Case("wait_for_scan", {"scan_id": _RANDOM_UUID, "timeout_s": 4000}, label="timeout_s=4000",
             expect="reject", names_arg="timeout_s"),
        Case("wait_for_scan", {"scan_id": _RANDOM_UUID, "poll_interval_s": 0.01}, label="poll_interval_s=0.01",
             expect="reject", names_arg="poll_interval_s"),
        Case("search_semantic", {"query": "login", "threshold": 2}, label="threshold=2", expect="reject",
             names_arg="threshold"),
        Case("search_smql", {"q": "   "}, label="blank query", expect="reject", names_arg="q"),
        Case("search_smql", {"q": "x" * 2001}, label="query > 2000 chars", expect="reject", names_arg="q"),
        Case("count_smql_queries", {"queries": []}, label="no queries", expect="should_reject", names_arg="queries"),
        Case("count_smql_queries", {"queries": ["title:login"] * 26}, label="26 queries", expect="should_reject",
             names_arg="queries"),
        Case("get_scan_graph", {"scan_ids": []}, label="no scan_ids", expect="should_reject", names_arg="scan_ids"),
        Case("get_scan_graph", {"scan_ids": [str(uuid.UUID(int=i, version=4)) for i in range(21)]},
             label="21 scan_ids", expect="should_reject", names_arg="scan_ids"),
        Case("search_scans", {"q": "ab"}, label="q shorter than 3", expect="should_reject", names_arg="q"),
        Case("search_ocr", {"q": "ab"}, label="q shorter than 3", expect="reject", names_arg="q"),
        Case("search_by_ip", {"ip_address": "999.1.1.1"}, label="invalid IP", expect="reject",
             names_arg="ip_address"),
        Case("get_ct_domains_by_ip", {"ip_address": "example.com"}, label="hostname as IP", expect="reject",
             names_arg="ip_address"),
        Case("search_by_asn", {"asn_number": 0}, label="asn_number=0", expect="reject", names_arg="asn_number"),
        Case("get_file_analysis", {"sha256": "abc"}, label="short sha256", expect="reject", names_arg="sha256"),
        Case("get_script_decoded_source", {"fingerprint_id": 1, "part": "../../etc"}, label="part traversal",
             expect="reject", names_arg="part"),
        Case("get_domain_stats", {"domain": ".."}, label="domain='..'", expect="reject", names_arg="domain"),
        Case("get_domain_stats", {"domain": "   "}, label="blank domain", expect="reject", names_arg="domain"),
        Case("get_capabilities_by_date", {"scan_date": "2026-13-45"}, label="impossible date",
             expect="should_reject", names_arg="scan_date"),
        Case("get_recent_scans", {"limit": 101}, label="limit=101", expect="should_reject", names_arg="limit"),
        Case("get_recent_scans", {"limit": 5, "qa_unknown_argument": 1}, label="unknown argument", expect="probe"),
    ]
    for case in specific:
        if case.tool in tools:
            add(case, f"specific:{case.tool}:{case.label}")
    return cases


def build_traversal_cases(tools: dict[str, dict[str, Any]]) -> list[Case]:
    """Every required free-text argument gets a value that tries to climb out of its URL segment."""
    cases = []
    payload = "qa-probe/../../../health"
    for name, tool in sorted(tools.items()):
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        base = _minimal_valid_args(name, props, required)
        for arg in required:
            spec = props.get(arg) or {}
            if _json_type(spec) != "string" or _enum_of(spec) or arg in {"scan_id", "url"}:
                continue
            cases.append(Case(name, {**base, arg: payload}, label=f"{arg} traversal", expect="traversal"))
    return cases


def _json_type(spec: dict[str, Any]) -> str | None:
    if "type" in spec:
        return spec["type"]
    types = [option.get("type") for option in spec.get("anyOf") or [] if option.get("type") != "null"]
    return types[0] if types else None


def _enum_of(spec: dict[str, Any]) -> list[Any] | None:
    if "enum" in spec:
        return spec["enum"]
    for option in spec.get("anyOf") or []:
        if "enum" in option:
            return option["enum"]
    return None


def _wrong_type_value(spec: dict[str, Any]) -> Any:
    kind = _json_type(spec)
    return {"string": 12345, "integer": "not-a-number", "number": "not-a-number", "array": "not-a-list",
            "boolean": "maybe", "object": "not-an-object"}.get(kind or "")


def _minimal_valid_args(name: str, props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    """Syntactically valid stand-ins, so an invalid-input case varies one argument at a time."""
    stand_ins = {
        "scan_id": _RANDOM_UUID, "fingerprint_id": 1, "ip_address": "192.0.2.1", "asn_number": 64496,
        "domain": "example.com", "name": "example.com", "q": "domain:example.com", "query": "login page",
        "queries": ["domain:example.com"], "scan_ids": [_RANDOM_UUID], "url": "https://example.com/",
        "scan_date": "2026-01-01", "hash_value": "0" * 32, "mmh3_hash": 1, "sha256": "0" * 64,
        "content_sha256": "0" * 64, "jarm_signature": "0" * 62, "pattern": "login", "cpe_pattern": "cpe:2.3:a:x",
        "value": "192.0.2.1",
    }
    if name == "search_similar_screenshots":
        stand_ins["hash_value"] = 1
    if name == "search_scans":
        stand_ins["q"] = "example"
    if name == "search_ocr":
        stand_ins["q"] = "password"
    args: dict[str, Any] = {}
    for arg in required:
        spec = props.get(arg) or {}
        enum = _enum_of(spec)
        if enum:
            args[arg] = "unlisted" if "unlisted" in enum else enum[0]
        elif arg in stand_ins:
            args[arg] = stand_ins[arg]
        elif _json_type(spec) == "integer":
            args[arg] = 1
        elif _json_type(spec) == "array":
            args[arg] = ["example"]
        else:
            args[arg] = "example"
    return args


# --------------------------------------------------------------------------------------
# Checks on a single tools/call answer
# --------------------------------------------------------------------------------------

_UPSTREAM_ERROR = re.compile(r"ScanMalware API error (\d{3}) for (\w+) (\S+?):")
_UPSTREAM_REQUEST_ERROR = re.compile(r"ScanMalware request error for (\w+) (\S+?): (.*)")
_LEAKS = {
    "traceback": re.compile(r"Traceback \(most recent call last\)|File \"/[^\"]+\.py\", line \d+"),
    "bearer token": re.compile(r"(?i)authorization:\s*bearer\s+\S|Bearer [A-Za-z0-9._~+/=-]{20,}"),
    "internal path or host": re.compile(r"/opt/scanmalware-mcp|/app/scanmalware_mcp|site-packages/|\bmitmproxy\b|"
                                        r"\bdeploy_mcp_1\b|https?://proxy[:/]"),
}
_RETRYABLE_UPSTREAM = {429, 502, 503, 504}


def _tool_text(result: dict[str, Any]) -> str:
    return "\n".join(str(block.get("text", "")) for block in result.get("content") or [] if block.get("type") == "text")


def _check_framing(reply: RpcReply, out: Result) -> bool:
    if reply.transport_error:
        out.add(FAIL, "transport", reply.transport_error)
        return False
    if reply.http_status != 200:
        out.add(FAIL, "http", f"HTTP {reply.http_status}: {reply.body_text[:200]!r}")
        return False
    content_type = reply.headers.get("content-type", "")
    if not (content_type.startswith("application/json") or content_type.startswith("text/event-stream")):
        out.add(FAIL, "http", f"unexpected content-type {content_type!r}")
    if "mcp-session-id" in reply.headers:
        out.add(FAIL, "stateless", "response carries an mcp-session-id header; the server is meant to be stateless")
    if reply.message is None:
        out.add(FAIL, "jsonrpc", f"no JSON-RPC response with id {reply.request_id}: {reply.body_text[:200]!r}")
        return False
    if reply.message.get("jsonrpc") != "2.0":
        out.add(FAIL, "jsonrpc", "response lacks jsonrpc: '2.0'")
    return True


def _check_leaks(text: str, out: Result) -> None:
    for label, pattern in _LEAKS.items():
        match = pattern.search(text)
        if match:
            out.add(FAIL, "leak", f"error text contains a {label}: {text[max(0, match.start() - 40):match.end() + 40]!r}")


def _validate_schema(instance: Any, schema: dict[str, Any] | None) -> list[str]:
    if not schema:
        return []
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - jsonschema ships with mcp
        return []
    validator_cls = jsonschema.validators.validator_for(schema, default=jsonschema.Draft202012Validator)
    validator = validator_cls(schema)
    return [f"{'/'.join(map(str, error.absolute_path)) or '(root)'}: {error.message[:160]}"
            for error in list(validator.iter_errors(instance))[:5]]


@dataclass
class Budgets:
    size_bytes: int = 100_000
    slow_s: float = 20.0


@dataclass
class Totals:
    """Aggregates for findings that only make sense across the whole run."""

    text_bytes: int = 0
    compact_bytes: int = 0
    structured_bytes: int = 0
    unknown_argument_accepted: bool | None = None


def check_ok_answer(reply: RpcReply, case: Case, args: dict[str, Any], tool: dict[str, Any] | None,
                    seeds: Seeds, budgets: Budgets, totals: Totals, out: Result) -> dict[str, Any] | None:
    if reply.error:
        out.add(FAIL, "jsonrpc-error", f"{reply.error.get('code')}: {str(reply.error.get('message'))[:300]}")
        return None
    result = reply.result
    if result is None:
        out.add(FAIL, "jsonrpc", "response has neither result nor error")
        return None
    text = _tool_text(result)
    if result.get("isError"):
        _classify_tool_error(text, out)
        _check_leaks(text, out)
        out.sample = text[:500]
        return None
    structured = result.get("structuredContent")
    if structured is None:
        out.add(FAIL, "structured", "no structuredContent, though the tool declares an outputSchema")
    elif not isinstance(structured, dict):
        out.add(FAIL, "structured", f"structuredContent is a {type(structured).__name__}, not an object")
    else:
        for problem in _validate_schema(structured, (tool or {}).get("outputSchema")):
            out.add(FAIL, "output-schema", problem)
    blocks = [block for block in result.get("content") or [] if block.get("type") == "text"]
    if not blocks:
        out.add(FAIL, "content", "no text content block; clients that ignore structuredContent see nothing")
    elif isinstance(structured, dict):
        try:
            parsed = [json.loads(block["text"]) for block in blocks]
        except (json.JSONDecodeError, KeyError):
            out.add(FAIL, "content", "a text block is not JSON")
        else:
            wrapped = structured.get("result") if set(structured) == {"result"} else None
            mirrors = (
                (len(parsed) == 1 and (parsed[0] == structured or parsed[0] == wrapped))
                or (wrapped is not None and parsed == wrapped)
                or (wrapped == [] and parsed == [])
            )
            if not mirrors:
                out.add(FAIL, "content", "text content does not carry the same data as structuredContent")
            totals.text_bytes += sum(len(block["text"].encode()) for block in blocks)
            totals.compact_bytes += sum(len(json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode())
                                        for item in parsed)
            totals.structured_bytes += len(json.dumps(structured, separators=(",", ":"), ensure_ascii=False).encode())
    data = structured if isinstance(structured, dict) else {}
    if set(data) == {"result"}:
        data_for_rows: Any = data["result"]
    else:
        data_for_rows = data
    if reply.body_bytes > budgets.size_bytes:
        out.add(WARN, "size", f"{reply.body_bytes / 1024:,.0f} KB on the wire (budget {budgets.size_bytes / 1024:,.0f} KB)")
    if reply.elapsed_s > budgets.slow_s:
        out.add(WARN, "slow", f"{reply.elapsed_s:.1f} s (budget {budgets.slow_s:.0f} s)")
    key, rows = _rows(data_for_rows)
    for limit_arg in ("limit", "per_page") if case.limit_rows else ():
        limit = args.get(limit_arg)
        if isinstance(limit, int) and rows is not None and len(rows) > limit:
            out.add(FAIL, "limit", f"{limit_arg}={limit} but {key or 'the answer'} holds {len(rows)} rows")
    if case.nonempty and not rows and not _has_counts(data):
        out.add(WARN, "empty", f"no rows for a value taken from live data ({key or 'no list'} is empty)")
    asked = args.get("scan_id")
    echoed = data.get("scan_id") if isinstance(data, dict) else None
    if isinstance(asked, str) and isinstance(echoed, str) and echoed.lower() != asked.lower():
        out.add(FAIL, "id-echo", f"asked for scan {asked}, answer is about {echoed}")
    if case.finds:
        needle = str(seeds.values.get(case.finds, "")).lower()
        if needle and needle not in json.dumps(structured).lower():
            out.add(WARN, "pivot-miss", f"the answer does not mention {case.finds}={needle}, the scan this pivot came from")
    if case.check is not None and isinstance(data, dict):
        for level, check, detail in case.check(data, args, seeds):
            out.add(level, check, detail)
    out.sample = json.dumps(structured, ensure_ascii=False)[:500]
    return structured if isinstance(structured, dict) else None


def _has_counts(data: Any) -> bool:
    # count_only answers and stats documents carry numbers rather than rows.
    return isinstance(data, dict) and any(
        isinstance(data.get(key), int) and data.get(key) > 0
        for key in ("count", "total", "total_count", "total_matches", "total_items", "total_results")
    )


def _is_unhandled(text: str) -> bool:
    # mcp 2.x prefixes every ToolError with "Error executing tool <name>: <message>". Only an
    # exception the server did not translate leaves the bare prefix, with no message at all.
    return bool(_BARE_TOOL_ERROR.fullmatch(text.strip()))


_BARE_TOOL_ERROR = re.compile(r"Error executing tool [\w.-]+(?:: Error executing tool [\w.-]+)*")


def _classify_tool_error(text: str, out: Result) -> None:
    match = _UPSTREAM_ERROR.search(text)
    if _is_unhandled(text):
        out.add(FAIL, "unhandled", f"the tool crashed with an exception the server did not translate: {text[:300]}")
    elif match:
        status = int(match.group(1))
        detail = text[:300]
        if status == 404:
            out.add(WARN, "upstream-404", f"the API has nothing for this input: {detail}")
        elif status == 429:
            out.add(WARN, "rate-limited", detail)
        elif status in (401, 403):
            out.add(FAIL, "upstream-auth", f"the API refused a public tool: {detail}")
        elif status in (400, 405, 422):
            out.add(FAIL, "upstream-rejected", f"the API rejected the request this tool built: {detail}")
        else:
            out.add(FAIL, "upstream-5xx" if status >= 500 else "upstream-error", detail)
    elif _UPSTREAM_REQUEST_ERROR.search(text):
        out.add(FAIL, "upstream-timeout", text[:300])
    else:
        out.add(FAIL, "tool-error", text[:300])


def check_rejection(reply: RpcReply, case: Case, upstream: list[str] | None, out: Result, totals: Totals) -> None:
    accepted = False
    if reply.error:
        code = reply.error.get("code")
        message = str(reply.error.get("message"))
        if code != -32602:
            out.add(FAIL, "jsonrpc-error", f"invalid input answered with JSON-RPC {code} (not -32602): {message[:200]}")
        out.note = f"JSON-RPC {code}"
        text = message + json.dumps(reply.error.get("data", ""))
    elif reply.result is not None and reply.result.get("isError"):
        text = _tool_text(reply.result)
        out.note = "tool error"
        if _is_unhandled(text):
            out.add(FAIL, "unhandled", f"invalid input crashed the tool: {text[:300]}")
        upstream_match = _UPSTREAM_ERROR.search(text)
        if upstream_match:
            accepted = True  # the API, not the server, refused it
            out.note = f"refused upstream ({upstream_match.group(1)})"
    else:
        text = _tool_text(reply.result or {})
        accepted = True
        out.note = "accepted"
    out.sample = text[:300]
    _check_leaks(text, out)
    if case.expect == "probe":
        if case.label == "unknown argument":
            totals.unknown_argument_accepted = accepted
        return
    reached_upstream = bool(upstream)
    if accepted or reached_upstream:
        level = FAIL if case.expect == "reject" else WARN
        where = "and the API was called" if reached_upstream else ""
        out.add(level, "accepted-invalid", f"the server did not refuse it {where}".strip() + f" ({out.note})")
    elif case.names_arg and case.names_arg.lower() not in text.lower():
        out.add(WARN, "unclear-error", f"the error does not mention {case.names_arg!r}: {text[:200]!r}")


def check_traversal(reply: RpcReply, upstream: list[str] | None, out: Result) -> None:
    if reply.error and reply.error.get("code") not in (-32602,):
        out.add(FAIL, "jsonrpc-error", str(reply.error)[:200])
    for entry in upstream or []:
        path = entry.split(" ")[1] if " " in entry else entry
        if "/../" in path or path.rstrip("/").endswith("/health") or "/qa-probe/" in path:
            out.add(FAIL, "traversal", f"the value left its URL segment: {entry}")
    if upstream is None:
        out.note = "no upstream trace (remote target)"
    else:
        out.note = "; ".join(upstream) or "refused before any upstream call"


# --------------------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------------------


@dataclass
class Options:
    url: str | None
    only: list[str]
    skip: list[str]
    allow_writes: bool
    write_url: str
    concurrency: int
    call_timeout_s: float
    invalid: str  # full | sample | none
    budgets: Budgets
    scan_id: str | None
    verbose: bool
    retries: int


class Runner:
    def __init__(self, client: McpHttp, opts: Options, tap: UpstreamTap | None) -> None:
        self.client = client
        self.opts = opts
        self.tap = tap
        self.seeds = Seeds()
        self.results: list[Result] = []
        self.tools: dict[str, dict[str, Any]] = {}
        self.totals = Totals()
        self.sem = asyncio.Semaphore(opts.concurrency)
        self.printer = Printer(verbose=opts.verbose)

    # -- plumbing ---------------------------------------------------------------------

    def selected(self, tool: str) -> bool:
        if self.opts.only and not any(fnmatch.fnmatch(tool, pattern) for pattern in self.opts.only):
            return False
        return not any(fnmatch.fnmatch(tool, pattern) for pattern in self.opts.skip)

    def record(self, result: Result) -> Result:
        self.results.append(result)
        self.printer.result(result)
        return result

    async def call(self, tool: str, args: Any, *, timeout_s: float | None = None) -> tuple[RpcReply, int]:
        """tools/call with retries on rate limits and transient upstream failures."""
        retries = 0
        while True:
            async with self.sem:
                reply = await self.client.call_tool(tool, args, timeout_s=timeout_s)
            text = _tool_text(reply.result or {}) if reply.result and reply.result.get("isError") else ""
            match = _UPSTREAM_ERROR.search(text)
            # A read timeout already cost a full --timeout; retrying it would triple that.
            dropped = bool(reply.transport_error) and "Timeout" not in (reply.transport_error or "")
            transient = bool(match and int(match.group(1)) in _RETRYABLE_UPSTREAM) or dropped
            if not transient or retries >= self.opts.retries:
                return reply, retries
            retries += 1
            await asyncio.sleep(3 * retries)

    async def upstream_of(self, reply: RpcReply) -> list[str] | None:
        if self.tap is None:
            return None
        event = await self.tap.get(reply.request_id)
        if event is None:
            return []
        return list(event.get("upstream") or [])

    async def seed_call(self, tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
        if tool not in self.tools:
            return None
        reply, _ = await self.call(tool, args)
        result = reply.result or {}
        if reply.message is None or result.get("isError"):
            return None
        structured = result.get("structuredContent")
        return structured if isinstance(structured, dict) else None

    # -- phases -----------------------------------------------------------------------

    async def run(self) -> None:
        self.printer.section("Handshake and tools/list")
        init = await self.client.initialize()
        info = self.client.server_info
        self.printer.line(f"server {info.get('name')!r} version {info.get('version')!r}, "
                          f"protocol {self.client.protocol_version}")
        tool_list, _ = await self.client.list_tools()
        self.tools = {tool["name"]: tool for tool in tool_list}
        self.printer.line(f"{len(self.tools)} tools")
        self.lint(tool_list, init)
        await self.protocol()
        self.printer.section("Seed values from live data")
        await self.seed()
        await self.tool_cases()
        if self.opts.invalid != "none":
            await self.invalid_cases()
        if self.tap is not None and self.opts.invalid == "full":
            await self.traversal_cases()
        await self.resources()

    def lint(self, tool_list: list[dict[str, Any]], init: RpcReply) -> None:
        self.printer.section("tools/list lint")
        names = [tool["name"] for tool in tool_list]
        write_tools = {"submit_scan", "submit_scan_report"}
        checks: dict[str, Result] = {}

        def flag(check: str, level: str, tool: str, detail: str) -> None:
            result = checks.setdefault(check, Result("lint", check, "all tools"))
            result.add(level, check, f"{tool}: {detail}")

        for dup in sorted({name for name in names if names.count(name) > 1}):
            flag("unique-names", FAIL, dup, "listed more than once")
        name_re = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
        other_names = set(names)
        for tool in tool_list:
            name = tool["name"]
            if not name_re.match(name):
                flag("name-format", FAIL, name, "not ^[A-Za-z0-9_-]{1,64}$ (Claude and OpenAI limit)")
            description = tool.get("description") or ""
            if len(description) < 60:
                flag("description", FAIL, name, f"description is {len(description)} characters (directory minimum 60)")
            if len(description) > 1024:
                flag("description-length", WARN, name, f"description is {len(description)} characters")
            for other in other_names - {name}:
                if re.search(rf"\b{re.escape(other)}\b", description):
                    flag("description-names-tool", WARN, name, f"description names another tool, {other}")
            if not (tool.get("title") or (tool.get("annotations") or {}).get("title")):
                flag("title", FAIL, name, "no title")
            schema = tool.get("inputSchema") or {}
            if schema.get("type") != "object":
                flag("input-schema", FAIL, name, "inputSchema.type is not 'object'")
            props = schema.get("properties") or {}
            for arg, spec in props.items():
                if not (spec.get("description") or "").strip():
                    flag("arg-descriptions", FAIL, name, f"argument {arg} has no description")
                if "default" in spec:
                    for problem in _validate_schema(spec["default"], {k: v for k, v in spec.items() if k != "default"}):
                        flag("defaults", FAIL, name, f"default of {arg} violates its own schema: {problem}")
            for arg in schema.get("required") or []:
                if arg not in props:
                    flag("input-schema", FAIL, name, f"required argument {arg} is not in properties")
            for arg in ("limit", "per_page"):
                spec = props.get(arg)
                if spec and "maximum" not in json.dumps(spec):
                    flag("bounds-in-schema", WARN, name, f"{arg} range is only in prose; the schema has no maximum")
            output = tool.get("outputSchema")
            if not output or output.get("type") != "object":
                flag("output-schema", FAIL, name, "no outputSchema of type object")
            annotations = tool.get("annotations") or {}
            read_only = annotations.get("readOnlyHint")
            if name in write_tools and read_only is not False:
                flag("annotations", FAIL, name, "writes to ScanMalware but readOnlyHint is not false")
            if name not in write_tools and read_only is not True:
                flag("annotations", FAIL, name, "read-only tool without readOnlyHint: true")
            if annotations.get("destructiveHint") is not False:
                flag("annotations", WARN, name, f"destructiveHint is {annotations.get('destructiveHint')!r}")
            if annotations.get("openWorldHint") is not True:
                flag("annotations", WARN, name, "openWorldHint is not true for a tool that calls an external API")
        planned = {case.tool for case in build_plan()}
        for name in sorted(set(names) - planned):
            flag("qa-coverage", FAIL, name, "served but has no case in qa/mcp_qa.py build_plan()")
        for name in sorted(planned - set(names)):
            flag("qa-coverage", WARN, name, "has a QA case but the server does not list it")
        for check in ("unique-names", "name-format", "description", "description-length", "description-names-tool",
                      "title", "input-schema", "arg-descriptions", "defaults", "bounds-in-schema", "output-schema",
                      "annotations", "qa-coverage"):
            result = checks.get(check) or Result("lint", check, "all tools")
            if result.issues and result.issues[0].check == "bounds-in-schema":
                count = len(result.issues)
                result.issues = result.issues[:3] + [Issue(WARN, check, f"... {count} tools in all")] if count > 3 else result.issues
            self.record(result)
        info = Result("lint", "initialize", "serverInfo and capabilities")
        init_result = init.result or {}
        if not (init_result.get("serverInfo") or {}).get("version"):
            info.add(FAIL, "server-info", "serverInfo.version is empty")
        if "tools" not in (init_result.get("capabilities") or {}):
            info.add(FAIL, "capabilities", "initialize does not advertise the tools capability")
        if not init_result.get("instructions"):
            info.add(WARN, "instructions", "no server instructions")
        if "mcp-session-id" in init.headers:
            info.add(FAIL, "stateless", "initialize answered with an mcp-session-id")
        self.record(info)

    async def protocol(self) -> None:
        self.printer.section("Protocol")
        http = self.client.http
        url = self.client.url

        async def probe(label: str, fn: Callable[[Result], Awaitable[None]]) -> None:
            result = Result("protocol", label, "")
            try:
                await fn(result)
            except Exception as exc:  # noqa: BLE001 - a probe must not stop the run
                result.add(FAIL, "probe-crashed", f"{type(exc).__name__}: {exc}"[:300])
            self.record(result)

        async def get_405(r: Result) -> None:
            response = await http.get(url, headers={"accept": "text/event-stream"}, timeout=15)
            if response.status_code != 405:
                r.add(FAIL, "get", f"GET /mcp answered {response.status_code}, not 405")
            elif "POST" not in response.headers.get("allow", ""):
                r.add(WARN, "get", "405 without Allow: POST")

        async def accept_406(r: Result) -> None:
            reply = await self.client.post({"jsonrpc": "2.0", "id": self.client.new_id(), "method": "ping"},
                                           headers={"accept": "text/html"})
            if reply.http_status != 406:
                r.add(FAIL, "accept", f"Accept: text/html answered {reply.http_status}, not 406")

        async def accept_wildcard(r: Result) -> None:
            reply = await self.client.post({"jsonrpc": "2.0", "id": self.client.new_id(), "method": "tools/list"},
                                           headers={"accept": "*/*"})
            if reply.http_status != 200 or reply.result is None:
                r.add(FAIL, "accept", f"Accept: */* answered {reply.http_status}: {_describe_reply(reply)}")

        async def ping(r: Result) -> None:
            reply = await self.client.request("ping")
            if reply.result != {}:
                r.add(FAIL, "ping", f"ping answered {_describe_reply(reply)}")

        async def unknown_method(r: Result) -> None:
            reply = await self.client.request("qa/no-such-method")
            if not reply.error or reply.error.get("code") != -32601:
                r.add(FAIL, "unknown-method", f"expected JSON-RPC -32601, got {_describe_reply(reply)}")

        async def unknown_tool(r: Result) -> None:
            reply = await self.client.call_tool("qa_no_such_tool", {})
            if reply.error is None and not (reply.result or {}).get("isError"):
                r.add(FAIL, "unknown-tool", "calling a tool that does not exist did not fail")
            r.note = _describe_reply(reply) if reply.error else _tool_text(reply.result or {})[:200]

        async def malformed(r: Result) -> None:
            reply = await self.client.post(b"{not json")
            code = (reply.error or {}).get("code")
            if reply.http_status not in (400, 200) or (reply.message is not None and code != -32700):
                r.add(FAIL, "parse-error", f"malformed JSON answered HTTP {reply.http_status}, {_describe_reply(reply)}")
            if reply.http_status and reply.http_status >= 500:
                r.add(FAIL, "parse-error", f"malformed JSON caused HTTP {reply.http_status}")

        async def unsupported_version(r: Result) -> None:
            reply = await self.client.request(
                "initialize", {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": CLIENT_INFO})
            version = (reply.result or {}).get("protocolVersion")
            if not version or version == "1999-01-01":
                r.add(FAIL, "version", f"an unknown protocolVersion was not countered with a supported one: "
                                       f"{_describe_reply(reply)}")
            r.note = f"server offered {version}"

        async def stable_list(r: Result) -> None:
            again, _ = await self.client.list_tools()
            first = json.dumps(sorted(self.tools.values(), key=lambda t: t["name"]), sort_keys=True)
            second = json.dumps(sorted(again, key=lambda t: t["name"]), sort_keys=True)
            if first != second:
                r.add(FAIL, "tools-list", "two tools/list calls returned different tool definitions")

        async def sdk(mode: str, want: str | None, r: Result) -> None:
            # The official client, as Claude Code and Claude.ai connect: "legacy" sends initialize,
            # "auto" probes server/discover first and only falls back to initialize when that fails.
            from mcp import Client
            from mcp.client.streamable_http import streamable_http_client
            from mcp.shared._httpx_utils import create_mcp_http_client

            http_client = create_mcp_http_client(headers={"User-Agent": USER_AGENT})
            async with http_client:
                transport = streamable_http_client(url, http_client=http_client)
                client = Client(transport, mode=mode, client_info=_implementation())
                async with client:
                    listed = await client.list_tools()
                    names = {tool.name for tool in listed.tools}
                    if names != set(self.tools):
                        r.add(FAIL, "sdk", f"{len(names)} tools over the SDK, {len(self.tools)} over raw JSON-RPC")
                    called = await client.call_tool("get_api_root", {})
                    if called.is_error:
                        r.add(FAIL, "sdk", f"get_api_root failed over the SDK: {called.content}")
                    negotiated = client.protocol_version
                    if want and negotiated != want:
                        r.add(FAIL, "sdk", f"negotiated {negotiated}, expected {want}")
                    r.note = f"{len(names)} tools, protocol {negotiated}"

        await probe("GET /mcp answers 405", get_405)
        await probe("Accept: text/html answers 406", accept_406)
        await probe("Accept: */* is accepted", accept_wildcard)
        await probe("ping", ping)
        await probe("unknown method is -32601", unknown_method)
        await probe("unknown tool fails cleanly", unknown_tool)
        await probe("malformed JSON is a parse error", malformed)
        await probe("unknown protocolVersion is countered", unsupported_version)
        await probe("tools/list is stable", stable_list)
        await probe("SDK client, initialize handshake (legacy)", lambda r: sdk("legacy", None, r))
        await probe(f"SDK client, server/discover ({MODERN_PROTOCOL})", lambda r: sdk("auto", MODERN_PROTOCOL, r))

    async def seed(self) -> None:
        seeds = self.seeds
        seeds.set("write_url", self.opts.write_url, "--write-target-url")
        result = Result("seed", "seed", "pick a scan and harvest pivots")
        recent = await self.seed_call("get_recent_scans", {"limit": 40}) or {}
        rows = [row for row in recent.get("results") or [] if row.get("status") == "completed"]
        candidates = [row["scan_id"] for row in rows[:10]]
        if self.opts.scan_id:
            candidates = [self.opts.scan_id] + [c for c in candidates if c != self.opts.scan_id]
        scored: list[tuple[int, str, dict[str, Any]]] = []
        pivots_by_scan: dict[str, dict[str, Any]] = {}
        pivot_answers = await asyncio.gather(*(self.seed_call("get_scan_pivot_values", {"scan_id": c})
                                               for c in candidates[:10]))
        for scan_id, pivots in zip(candidates[:10], pivot_answers):
            if not pivots:
                continue
            pivots_by_scan[scan_id] = pivots
            score = sum(1 for value in pivots.values() if isinstance(value, list) and value)
            score += 3 * bool(pivots.get("scripts")) + 2 * bool(pivots.get("tracking_keys"))
            scored.append((score, scan_id, pivots))
        if self.opts.scan_id:
            chosen = self.opts.scan_id
        elif scored:
            chosen = max(scored)[1]
        else:
            result.add(FAIL, "seed", "no completed scan found among the recent scans; pass --scan-id")
            self.record(result)
            return
        seeds.set("scan_id", chosen, "--scan-id" if self.opts.scan_id else "richest of the recent completed scans")
        others = [scan_id for _, scan_id, _ in sorted(scored, reverse=True) if scan_id != chosen]
        if others:
            seeds.set("scan_id_2", others[0], "second richest recent scan")

        (scan, rdap, jarm, favicon, cpe, tech, runtime, tracking, high_risk, dns, lib_hit, obf) = await asyncio.gather(
            self.seed_call("get_scan_result", {"scan_id": chosen}),
            self.seed_call("get_rdap", {"scan_id": chosen}),
            self.seed_call("get_jarm_signatures", {"scan_id": chosen}),
            self.seed_call("get_favicon", {"scan_id": chosen}),
            self.seed_call("get_cpe_by_scan", {"scan_id": chosen}),
            self.seed_call("get_technologies_by_scan", {"scan_id": chosen}),
            self.seed_call("get_js_runtime_behaviour", {"scan_id": chosen}),
            self.seed_call("get_top_tracking_keys", {"limit": 5}),
            self.seed_call("search_ai_high_risk", {"limit": 5}),
            self.seed_call("get_scan_dns", {"scan_id": chosen}),
            self.seed_call("search_jsfingerprints_by_library", {"library": "jquery", "limit": 1}),
            self.seed_call("search_js_fingerprint_obfuscated", {"per_page": 1}),
        )
        scan = scan or {}
        url = scan.get("final_url") or scan.get("url")
        seeds.set("host", _host(url), "get_scan_result final_url")
        seeds.set("domain", (dns or {}).get("summary", {}).get("domain"), "get_scan_dns summary.domain")
        seeds.set("domain", (rdap or {}).get("domain"), "get_rdap domain")
        seeds.set("domain", _host(url), "get_scan_result final_url")
        seeds.set("ip", scan.get("primary_ip"), "get_scan_result primary_ip")
        if isinstance(scan.get("primary_asn"), int):
            seeds.set("asn", scan["primary_asn"], "get_scan_result primary_asn")
        shots = scan.get("screenshot_hashes") or {}
        seeds.set("phash_hex", shots.get("phash_hex"), "get_scan_result screenshot_hashes.phash_hex")
        if str(shots.get("phash_int") or "").isdigit():
            seeds.set("phash_int", int(shots["phash_int"]), "get_scan_result screenshot_hashes.phash_int")
        seeds.set("tlsh", (scan.get("fuzzy_hashes") or {}).get("tlsh"), "get_scan_result fuzzy_hashes.tlsh")
        await self._seed_favicon(chosen, scan, favicon, others)
        nameservers = (rdap or {}).get("nameservers") or []
        seeds.set("nameserver", nameservers[0] if nameservers else None, "get_rdap nameservers[0]")
        seeds.set("registrar", (rdap or {}).get("registrar"), "get_rdap registrar")
        seeds.set("registrar", "GoDaddy.com, LLC", "fallback (the seed scan has no RDAP registrar)")
        signatures = (jarm or {}).get("signatures") or []
        seeds.set("jarm", next((s.get("jarm_signature") for s in signatures if s.get("jarm_signature")), None),
                  "get_jarm_signatures signatures[].jarm_signature")
        cpes = (cpe or {}).get("result") or []
        if cpes and isinstance(cpes[0], dict) and cpes[0].get("cpe"):
            seeds.set("cpe_pattern", ":".join(cpes[0]["cpe"].split(":")[:5]), "get_cpe_by_scan result[0].cpe prefix")
        technologies = (tech or {}).get("technologies") or []
        seeds.set("tech_name", technologies[0].get("name") if technologies else None, "get_technologies_by_scan")
        seeds.set("tech_name", "WordPress", "fallback")
        # Behavioural (runtime) pivots: the seed scan's own, else the first other candidate that has
        # them. The API answers 400 "Target scan has no behavioral fingerprint" for scans without.
        behavioral = _first(runtime or {}, "behavioral") or {}
        runtime_scan = chosen if behavioral.get("compositeHash") else None
        for scan_id in [] if runtime_scan else others[:5]:
            answer = await self.seed_call("get_js_runtime_behaviour", {"scan_id": scan_id}) or {}
            behavioral = _first(answer, "behavioral") or {}
            if behavioral.get("compositeHash"):
                runtime_scan = scan_id
                break
        source = f"get_js_runtime_behaviour ({'seed scan' if runtime_scan == chosen else 'first candidate with one'})"
        seeds.set("runtime_scan_id", runtime_scan, source)
        seeds.set("runtime_composite", behavioral.get("compositeHash"), f"{source} compositeHash")
        seeds.set("runtime_signature", behavioral.get("signature"), f"{source} signature")
        top = ((tracking or {}).get("results") or [{}])[0]
        seeds.set("tracker_type", top.get("tracker_type"), "get_top_tracking_keys results[0]")
        seeds.set("tracker_key", top.get("tracking_key"), "get_top_tracking_keys results[0]")
        seeds.set("scam_type", _first(high_risk or {}, "scam_type"), "search_ai_high_risk results[].scam_type")
        seeds.set("scam_type", "Phishing", "fallback")

        # JavaScript: start from a jQuery file that is certainly in the index.
        lib_row = ((lib_hit or {}).get("results") or [{}])[0]
        seeds.set("js_library", lib_row.get("library_name"), "search_jsfingerprints_by_library jquery")
        seeds.set("js_library_version", lib_row.get("library_version"), "search_jsfingerprints_by_library jquery")
        seeds.set("js_library", "jquery", "fallback")
        seeds.set("js_library_version", "3.7.1", "fallback")
        sha = lib_row.get("content_sha256")
        if sha:
            by_sha = await self.seed_call("search_js_fingerprint_by_sha256", {"hash_value": sha, "limit": 1}) or {}
            match = ((by_sha.get("matches") or [{}])[0])
            seeds.set("fp_id", match.get("fingerprint_id"), "search_js_fingerprint_by_sha256 matches[0]")
            seeds.set("fp_scan_id", match.get("scan_id"), "search_js_fingerprint_by_sha256 matches[0]")
        seeds.set("fp_id", 10448358, "fallback (fingerprint used by tests/test_server.py)")
        fingerprint = await self.seed_call("get_jsfingerprint", {"fingerprint_id": seeds.values["fp_id"]}) or {}
        hashes = fingerprint.get("hashes") or {}
        seeds.set("fp_scan_id", fingerprint.get("scan_id"), "get_jsfingerprint scan_id")
        for key, source_key in (("fp_sha256", "sha256"), ("fp_md5", "md5"), ("fp_sha1", "sha1"),
                                ("fp_normalized", "normalized"), ("fp_fuzzy", "fuzzy")):
            seeds.set(key, hashes.get(source_key), f"get_jsfingerprint hashes.{source_key}")
        script = ((obf or {}).get("scripts") or [{}])[0]
        seeds.set("obf_fp_id", script.get("fingerprint_id"), "search_js_fingerprint_obfuscated scripts[0]")
        seeds.set("obf_scan_id", script.get("scan_id"), "search_js_fingerprint_obfuscated scripts[0]")

        # Code segments: the first scan, of the seed, fingerprint and obfuscated ones, that has any.
        for scan_id in dict.fromkeys(filter(None, [chosen, seeds.values.get("fp_scan_id"),
                                                   seeds.values.get("obf_scan_id"), *others[:3]])):
            segments = await self.seed_call("get_js_segments_by_scan", {"scan_id": scan_id, "limit": 1}) or {}
            row = ((segments.get("segments") or [{}])[0])
            if row:
                seeds.set("segment_scan_id", scan_id, "get_js_segments_by_scan (first scan with segments)")
                seeds.set("segment_code_hash", _first(row, "code_hash", "hash"), "get_js_segments_by_scan segments[0]")
                seeds.set("segment_normalized_hash", _first(row, "normalized_hash"),
                          "get_js_segments_by_scan segments[0]")
                break

        # A downloaded file: the seed scan's own, else the newest scan that fetched an .exe.
        pivots = pivots_by_scan.get(chosen) or {}
        seeds.set("file_sha256", _first(pivots.get("files") or [], "sha256"), "seed scan pivot values files[0]")
        if "file_sha256" not in seeds:
            hits = await self.seed_call("search_smql", {"q": "file_name:*.exe", "limit": 1}) or {}
            file_scan = _first(hits.get("results") or [], "scan_id")
            if file_scan:
                file_pivots = await self.seed_call("get_scan_pivot_values", {"scan_id": file_scan}) or {}
                seeds.set("file_sha256", _first(file_pivots.get("files") or [], "sha256"),
                          "search_smql file_name:*.exe, then its pivot values files[0]")

        for key in sorted(seeds.values):
            value = seeds.values[key]
            self.printer.line(f"  {key:<24} {str(value)[:70]:<72} [{seeds.sources[key]}]")
        wanted = {"scan_id", "domain", "ip", "asn", "jarm", "fp_id", "fp_sha256", "segment_code_hash", "obf_fp_id"}
        missing = sorted(wanted - set(seeds.values))
        if missing:
            result.add(WARN, "seed", f"no live value for {missing}; the tools that need them are skipped")
        result.note = f"scan {chosen}"
        result.args = {key: seeds.values[key] for key in sorted(seeds.values)}
        self.record(result)

    async def _seed_favicon(self, chosen: str, scan: dict[str, Any], favicon: dict[str, Any] | None,
                            others: list[str]) -> None:
        """Favicon pivots from the first candidate scan that has a favicon.

        get_scan_result's favicon_hash.md5_hash is the original file's, the one search indexes.
        get_favicon's md5 must be the same: until PR #28 it was a hash of the served copy, which
        changes on every request and was never found. Both are seeded, and the plan checks that
        search_by_favicon finds each of them.
        """
        for scan_id in [chosen, *others[:4]]:
            served = favicon if scan_id == chosen else await self.seed_call("get_favicon", {"scan_id": scan_id})
            if not (served or {}).get("found"):
                continue
            result = scan if scan_id == chosen else await self.seed_call("get_scan_result", {"scan_id": scan_id})
            original = (result or {}).get("favicon_hash") or {}
            source = f"scan {scan_id[:8]}"
            self.seeds.set("favicon_md5", original.get("md5_hash"), f"get_scan_result favicon_hash.md5_hash ({source})")
            self.seeds.set("favicon_md5_served", served.get("md5"), f"get_favicon md5 ({source})")
            mmh3 = original.get("mmh3_hash")
            if mmh3 is not None and str(mmh3).lstrip("-").isdigit():
                self.seeds.set("favicon_mmh3", int(mmh3), f"get_scan_result favicon_hash.mmh3_hash ({source})")
                self.seeds.set("favicon_mmh3_text", str(mmh3), f"get_scan_result favicon_hash.mmh3_hash ({source})")
            return

    async def run_case(self, case: Case, section: str) -> Result:
        out = Result(section, case.tool, case.label)
        try:
            args = resolve(case.args, self.seeds)
        except MissingSeed as missing:
            out.status = SKIP
            out.note = f"no seed value for ${missing.args[0]}"
            return self.record(out)
        out.args = args
        timeout = case.timeout_s or self.opts.call_timeout_s
        reply, retries = await self.call(case.tool, args, timeout_s=timeout)
        out.elapsed_s = reply.elapsed_s
        out.body_bytes = reply.body_bytes
        out.upstream = await self.upstream_of(reply)
        if retries:
            out.note = f"{retries} retr{'y' if retries == 1 else 'ies'}"
        if not _check_framing(reply, out):
            return self.record(out)
        if case.expect == "ok":
            structured = check_ok_answer(reply, case, args, self.tools.get(case.tool), self.seeds, self.opts.budgets,
                                         self.totals, out)
            if out.upstream is not None:
                self._check_upstream_trace(out)
            if case.tool == "submit_scan" and structured:
                self.seeds.set("new_scan_id", structured.get("scan_id") or structured.get("id"), "submit_scan")
        elif case.expect == "traversal":
            check_traversal(reply, out.upstream, out)
        else:
            check_rejection(reply, case, out.upstream, out, self.totals)
        return self.record(out)

    def _check_upstream_trace(self, out: Result) -> None:
        if out.status == FAIL:
            return
        if not out.upstream:
            out.add(WARN, "upstream-trace", "no upstream request recorded for a tool that wraps the API")
        for entry in out.upstream or []:
            parts = entry.split(" ")
            if len(parts) >= 2 and not parts[1].startswith("/api/v1/"):
                out.add(FAIL, "upstream-trace", f"request outside /api/v1/: {entry}")

    async def tool_cases(self) -> None:
        self.printer.section("Tools: one call or more per tool, with live values")
        plan = [case for case in build_plan() if self.selected(case.tool) and case.tool in self.tools]
        reads = [case for case in plan if not case.write]
        await asyncio.gather(*(self.run_case(case, "tools") for case in reads))
        writes = [case for case in plan if case.write]
        if not writes:
            return
        self.printer.section("Writes")
        for case in writes:
            if not self.opts.allow_writes:
                self.record(Result("writes", case.tool, case.label, status=SKIP,
                                   note="writes to ScanMalware; run with --allow-writes"))
                continue
            await self.run_case(case, "writes")

    async def invalid_cases(self) -> None:
        self.printer.section(f"Invalid input ({self.opts.invalid})")
        tools = {name: tool for name, tool in self.tools.items() if self.selected(name)}
        cases = build_invalid_cases(tools, sample=self.opts.invalid == "sample")
        await asyncio.gather(*(self.run_case(case, "invalid") for case in cases))

    async def traversal_cases(self) -> None:
        self.printer.section("Path traversal in free-text arguments (local: checked against the upstream trace)")
        tools = {name: tool for name, tool in self.tools.items() if self.selected(name)}
        await asyncio.gather(*(self.run_case(case, "traversal") for case in build_traversal_cases(tools)))

    async def resources(self) -> None:
        self.printer.section("Resources")
        reply = await self.client.request("resources/templates/list")
        listing = Result("resources", "resources/templates/list", "")
        templates = (reply.result or {}).get("resourceTemplates") or []
        if reply.result is None:
            listing.add(FAIL, "templates", _describe_reply(reply))
        listing.note = ", ".join(t.get("uriTemplate", "?") for t in templates)
        self.record(listing)
        scan_id = self.seeds.values.get("scan_id")
        reads: list[tuple[str, str, Callable[[bytes], bool], str]] = []
        for template in templates:
            uri_template = template.get("uriTemplate", "")
            if "{scan_id}" in uri_template and scan_id:
                uri = uri_template.replace("{scan_id}", scan_id)
            elif "{feed}" in uri_template:
                uri = uri_template.replace("{feed}", "rss")
            else:
                continue
            mime = template.get("mimeType", "")
            reads.append((uri, mime, _magic_for(uri, mime), "ok"))
        reads.append(("scanmalware://screenshot/not-a-uuid.png", "", lambda _: True, "reject"))
        reads.append(("scanmalware://rss/qa-no-such-feed.xml", "", lambda _: True, "reject"))
        await asyncio.gather(*(self.read_resource(*item) for item in reads))

    async def read_resource(self, uri: str, mime: str, magic: Callable[[bytes], bool], expect: str) -> None:
        out = Result("resources", uri, "read" if expect == "ok" else "invalid URI")
        async with self.sem:
            reply = await self.client.request("resources/read", {"uri": uri})
        out.elapsed_s, out.body_bytes = reply.elapsed_s, reply.body_bytes
        if not _check_framing(reply, out):
            self.record(out)
            return
        if expect == "reject":
            if reply.result is not None and not reply.error:
                out.add(FAIL, "accepted-invalid", "an invalid resource URI was read without error")
            else:
                _check_leaks(str(reply.error), out)
                out.note = str((reply.error or {}).get("message"))[:160]
            self.record(out)
            return
        if reply.error:
            message = str(reply.error.get("message"))
            level = WARN if " 404 " in message or "404" in message[:80] else FAIL
            out.add(level, "upstream-404" if level == WARN else "resource-error", message[:300])
            _check_leaks(message, out)
            self.record(out)
            return
        contents = (reply.result or {}).get("contents") or []
        if not contents:
            out.add(FAIL, "resource", "no contents")
        for item in contents[:1]:
            if mime and item.get("mimeType") != mime:
                out.add(FAIL, "mime", f"mimeType {item.get('mimeType')!r}, template says {mime!r}")
            if "blob" in item:
                try:
                    data = base64.b64decode(item["blob"], validate=True)
                except ValueError:
                    out.add(FAIL, "blob", "blob is not valid base64")
                    data = b""
            else:
                data = str(item.get("text", "")).encode()
            if not magic(data):
                kind = "gzip data" if data[:2] == b"\x1f\x8b" else repr(data[:16])
                out.add(FAIL, "content", f"bytes are {kind}, not the {uri.rsplit('.', 1)[-1]} that the URI and "
                                         f"mimeType {item.get('mimeType')!r} promise")
            out.note = f"{len(data):,} bytes {item.get('mimeType')}"
        if reply.body_bytes > self.opts.budgets.size_bytes * 10:
            out.add(WARN, "size", f"{reply.body_bytes / 1024:,.0f} KB on the wire")
        self.record(out)


def _magic_for(uri: str, mime: str = "") -> Callable[[bytes], bool]:
    """A check that the bytes are what the URI and the declared mimeType say they are."""
    if mime == "application/gzip":
        inner_check = _magic_for(uri, "")

        def gzip_check(data: bytes) -> bool:
            if data[:2] != b"\x1f\x8b":
                return False
            try:
                head = zlib.decompressobj(31).decompress(data, 64)
            except zlib.error:
                return False
            return inner_check(head)

        return gzip_check
    if uri.endswith(".png"):
        return lambda data: data.startswith(b"\x89PNG\r\n\x1a\n")
    if uri.endswith(".pem"):
        return lambda data: b"-----BEGIN CERTIFICATE-----" in data
    if uri.endswith(".pcap"):
        return lambda data: data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
                                         b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if uri.endswith(".xml"):
        return lambda data: b"<rss" in data[:2000] or b"<feed" in data[:2000]
    return lambda data: bool(data)


def _implementation() -> Any:
    from mcp.types import Implementation

    return Implementation(**CLIENT_INFO)


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


class Printer:
    COLORS = {PASS: "32", WARN: "33", FAIL: "31", SKIP: "90"}

    def __init__(self, *, verbose: bool) -> None:
        self.verbose = verbose
        self.color = sys.stdout.isatty() and not os.getenv("NO_COLOR")

    def paint(self, text: str, status: str) -> str:
        return f"\033[{self.COLORS[status]}m{text}\033[0m" if self.color else text

    def section(self, title: str) -> None:
        print(f"\n== {title}", flush=True)

    def line(self, text: str, *, always: bool = True) -> None:
        if always:
            print(text, flush=True)

    def result(self, result: Result) -> None:
        if result.status == PASS and not self.verbose and result.section in {"invalid", "traversal"}:
            return
        timing = f"{result.elapsed_s:5.1f}s" if result.elapsed_s is not None else "      "
        size = f"{result.body_bytes / 1024:8.1f}KB" if result.body_bytes is not None else "          "
        label = f"{result.subject} [{result.label}]" if result.label else result.subject
        tail = f"  {result.note}" if result.note and (self.verbose or result.status != PASS) else ""
        print(f"{self.paint(f'{result.status:4}', result.status)} {timing} {size}  {label}{tail}", flush=True)
        for issue in result.issues if result.status != PASS else []:
            print(f"       {self.paint(issue.level, issue.level)} {issue.check}: {issue.detail[:400]}", flush=True)


def summarize(runner: Runner, target: str, started: float) -> dict[str, Any]:
    results = runner.results
    counts = {status: sum(1 for r in results if r.status == status) for status in (PASS, WARN, FAIL, SKIP)}
    by_check: dict[str, list[str]] = {}
    for result in results:
        for issue in result.issues:
            by_check.setdefault(f"{issue.level} {issue.check}", []).append(
                f"{result.subject}" + (f" [{result.label}]" if result.label not in ("", "basic") else ""))
    tool_results = [r for r in results if r.section in {"tools", "writes"}]
    exercised = {r.subject for r in tool_results if r.status != SKIP}
    largest = sorted((r for r in tool_results if r.body_bytes), key=lambda r: r.body_bytes or 0, reverse=True)[:8]
    slowest = sorted((r for r in tool_results if r.elapsed_s), key=lambda r: r.elapsed_s or 0, reverse=True)[:8]
    totals = runner.totals
    print("\n== Summary")
    print(f"target {target}")
    print(f"{len(runner.tools)} tools listed, {len(exercised)} exercised with live values; "
          f"{len(results)} checks in {time.time() - started:.0f} s")
    print("  ".join(runner.printer.paint(f"{status} {counts[status]}", status) for status in (PASS, WARN, FAIL, SKIP)))
    if by_check:
        print("\nFindings by check (count, examples):")
        for key in sorted(by_check, key=lambda k: (not k.startswith(FAIL), -len(by_check[k]))):
            examples = sorted(set(by_check[key]))
            print(f"  {key:<34} {len(by_check[key]):>4}  {', '.join(examples[:6])}{' ...' if len(examples) > 6 else ''}")
    print("\nLargest answers:")
    for r in largest:
        print(f"  {r.body_bytes / 1024:10,.1f} KB  {r.subject} [{r.label}]")
    print("Slowest answers:")
    for r in slowest:
        print(f"  {r.elapsed_s:10.1f} s   {r.subject} [{r.label}]")
    if totals.text_bytes:
        saved = 1 - totals.compact_bytes / totals.text_bytes
        print(f"\nText blocks: {totals.text_bytes / 1e6:.1f} MB as sent; compact JSON would be "
              f"{totals.compact_bytes / 1e6:.1f} MB ({saved:.0%} smaller). Each answer also repeats the data as "
              f"structuredContent ({totals.structured_bytes / 1e6:.1f} MB compact).")
    if totals.unknown_argument_accepted is not None:
        print("Unknown tool arguments are " + ("silently ignored (a misspelt limit is not reported)."
                                               if totals.unknown_argument_accepted else "rejected."))
    skipped = [r for r in results if r.status == SKIP]
    if skipped:
        print("\nSkipped: " + ", ".join(sorted({f"{r.subject} ({r.note})" for r in skipped})))
    return {
        "target": target,
        "server_info": runner.client.server_info,
        "protocol_version": runner.client.protocol_version,
        "tool_count": len(runner.tools),
        "tools_exercised": sorted(exercised),
        "counts": counts,
        "seeds": {key: {"value": value, "source": runner.seeds.sources.get(key)}
                  for key, value in runner.seeds.values.items()},
        "findings_by_check": {key: sorted(set(value)) for key, value in by_check.items()},
        "text_bytes": totals.text_bytes,
        "compact_text_bytes": totals.compact_bytes,
        "structured_bytes": totals.structured_bytes,
        "unknown_argument_accepted": totals.unknown_argument_accepted,
        "results": [r.to_json() for r in results],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "qa_version": QA_VERSION,
    }


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def parse_args(argv: list[str] | None) -> tuple[Options, argparse.Namespace]:
    parser = argparse.ArgumentParser(prog="mcp_qa", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--local", action="store_true", help="test this checkout in-process (default)")
    target.add_argument("--url", help="test a deployed endpoint, e.g. https://mcp.scanmalware.com/mcp")
    parser.add_argument("--only", action="append", default=[], metavar="GLOB", help="only these tools (repeatable)")
    parser.add_argument("--skip", action="append", default=[], metavar="GLOB", help="skip these tools (repeatable)")
    parser.add_argument("--allow-writes", action="store_true",
                        help="also submit one unlisted scan and cast one positive_feedback vote on it")
    parser.add_argument("--write-target-url", default="https://example.com/", help="URL scanned by --allow-writes")
    parser.add_argument("--scan-id", help="seed scan to use instead of picking one from the recent scans")
    parser.add_argument("--invalid", choices=["full", "sample", "none"],
                        help="invalid-input cases: full (default locally), sample (default remotely), none")
    parser.add_argument("--concurrency", type=int, default=4, help="parallel calls (default 4)")
    parser.add_argument("--timeout", type=float, default=150, help="seconds per call (default 150)")
    parser.add_argument("--retries", type=int, default=2,
                        help="retries on upstream 429/502/503/504 and dropped connections, not on read timeouts "
                             "(default 2)")
    parser.add_argument("--size-budget-kb", type=int, default=100,
                        help="warn when one answer is larger (default 100 KB, roughly 25k tokens)")
    parser.add_argument("--slow-s", type=float, default=20, help="warn when one call is slower (default 20 s)")
    parser.add_argument("--report", type=Path, help="write the full JSON report here")
    parser.add_argument("--probe", nargs=2, metavar=("TOOL", "JSON_ARGS"), help="call one tool and print the answer")
    parser.add_argument("-v", "--verbose", action="store_true", help="print passing checks and seed values too")
    ns = parser.parse_args(argv)
    if ns.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    invalid = ns.invalid or ("sample" if ns.url else "full")
    opts = Options(
        url=ns.url, only=ns.only, skip=ns.skip, allow_writes=ns.allow_writes, write_url=ns.write_target_url,
        concurrency=ns.concurrency, call_timeout_s=ns.timeout, invalid=invalid,
        budgets=Budgets(size_bytes=ns.size_budget_kb * 1024, slow_s=ns.slow_s), scan_id=ns.scan_id,
        verbose=ns.verbose, retries=ns.retries,
    )
    return opts, ns


async def amain(argv: list[str] | None = None) -> int:
    opts, ns = parse_args(argv)
    started = time.time()
    async with contextlib.AsyncExitStack() as stack:
        tap: UpstreamTap | None = None
        if opts.url:
            url = opts.url
        else:
            local = await stack.enter_async_context(LocalServer())
            url, tap = local.url, local.tap
        http = await stack.enter_async_context(httpx.AsyncClient(headers={"user-agent": USER_AGENT}))
        client = McpHttp(url, http, call_timeout_s=opts.call_timeout_s)
        if ns.probe:
            await client.initialize()
            reply = await client.call_tool(ns.probe[0], json.loads(ns.probe[1]))
            print(json.dumps(reply.message, indent=2, ensure_ascii=False))
            if tap is not None:
                event = await tap.get(reply.request_id)
                print("upstream:", (event or {}).get("upstream"), file=sys.stderr)
            print(f"{reply.elapsed_s:.2f} s, {reply.body_bytes:,} bytes", file=sys.stderr)
            return 0
        runner = Runner(client, opts, tap)
        print(f"ScanMalware MCP QA {QA_VERSION}: {'local checkout at ' + str(REPO_ROOT) if tap else url}")
        try:
            await runner.run()
        except HarnessError as exc:
            print(f"\nHARNESS ERROR: {exc}", file=sys.stderr)
            return 2
        report = summarize(runner, url if not tap else f"local ({REPO_ROOT}, upstream {_upstream_base()})", started)
    if ns.report:
        ns.report.parent.mkdir(parents=True, exist_ok=True)
        ns.report.write_text(json.dumps(report, indent=1, ensure_ascii=False, default=str))
        print(f"\nJSON report: {ns.report}")
    return 1 if report["counts"][FAIL] else 0


def _upstream_base() -> str:
    return os.getenv("SCANMALWARE_BASE_URL", "https://scanmalware.com")


def main() -> None:
    try:
        sys.exit(asyncio.run(amain()))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
