"""Enforce the proxy destination policy before connecting upstream.

mitmproxy's allow_hosts controls interception, not access: other hosts can be
tunneled without inspection. Both CONNECT and ordinary requests need a guard.
"""
from __future__ import annotations

import json
import os
import re
import time

from mitmproxy import http


_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*scanmalware\.com")


def _log_blocked(flow: http.HTTPFlow) -> None:
    # log_full.py records completed exchanges only, and a refused CONNECT (the
    # path any HTTPS client takes) never becomes one, so blocked HTTPS
    # destinations left no trace. Record every refusal here, in the same file.
    # The MCP server only calls scanmalware.com, so each line is code in the
    # container, or an egress check, trying another destination.
    peer = getattr(getattr(flow, "client_conn", None), "peername", None)
    entry = {
        "event": "proxy.blocked",
        "timestamp": time.time(),
        "id": getattr(flow, "id", None),
        "method": flow.request.method,
        "host": flow.request.host,
        "port": flow.request.port,
        "client": list(peer) if peer else None,
    }
    try:
        with open(os.getenv("MITMPROXY_FULL_LOG", "/var/log/mitmproxy/full.log"), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass  # never let logging stand in the way of the block


def _reject_unless_allowed(flow: http.HTTPFlow) -> None:
    host = flow.request.host.lower().rstrip(".")
    allowed_ports = (443,) if flow.request.method == "CONNECT" else (80, 443)
    if not _HOST.fullmatch(host) or flow.request.port not in allowed_ports:
        flow.response = http.Response.make(
            403,
            b"Proxy destination is not permitted.\n",
            {"Content-Type": "text/plain"},
        )
        _log_blocked(flow)


def http_connect(flow: http.HTTPFlow) -> None:
    _reject_unless_allowed(flow)


def requestheaders(flow: http.HTTPFlow) -> None:
    _reject_unless_allowed(flow)
