"""Enforce the proxy destination policy before connecting upstream.

mitmproxy's allow_hosts controls interception, not access: other hosts can be
tunneled without inspection. Both CONNECT and ordinary requests need a guard.
"""
from __future__ import annotations

import re

from mitmproxy import http


_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*scanmalware\.com")


def _reject_unless_allowed(flow: http.HTTPFlow) -> None:
    host = flow.request.host.lower().rstrip(".")
    allowed_ports = (443,) if flow.request.method == "CONNECT" else (80, 443)
    if not _HOST.fullmatch(host) or flow.request.port not in allowed_ports:
        flow.response = http.Response.make(
            403,
            b"Proxy destination is not permitted.\n",
            {"Content-Type": "text/plain"},
        )


def http_connect(flow: http.HTTPFlow) -> None:
    _reject_unless_allowed(flow)


def requestheaders(flow: http.HTTPFlow) -> None:
    _reject_unless_allowed(flow)
