from __future__ import annotations

import base64
import json
import os
from typing import Any

from mitmproxy import ctx, http


LOG_PATH = os.getenv("MITMPROXY_FULL_LOG", "/var/log/mitmproxy/full.log")
LOG_DIR = os.path.dirname(LOG_PATH)
if LOG_DIR:
    os.makedirs(LOG_DIR, exist_ok=True)


def _b64(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    return {
        "base64": base64.b64encode(data).decode("ascii"),
        "length": len(data),
    }


def _headers(headers: http.Headers) -> list[list[str]]:
    return [[name, value] for name, value in headers.items(multi=True)]


def _client_info(flow: http.HTTPFlow) -> dict[str, Any] | None:
    conn = flow.client_conn
    if conn is None:
        return None
    return {
        "peername": conn.peername,
        "sockname": conn.sockname,
        "connected_at": conn.timestamp_start,
        "tls_established_at": conn.timestamp_tls_setup,
    }


def _server_info(flow: http.HTTPFlow) -> dict[str, Any] | None:
    conn = flow.server_conn
    if conn is None:
        return None
    return {
        "address": conn.address,
        "peername": conn.peername,
        "connected_at": conn.timestamp_start,
        "tls_established_at": conn.timestamp_tls_setup,
    }


def _message_body(message: http.Message) -> dict[str, Any] | None:
    data = message.raw_content
    if data is None:
        data = message.content
    return _b64(data)


def _request_payload(flow: http.HTTPFlow) -> dict[str, Any]:
    req = flow.request
    return {
        "method": req.method,
        "scheme": req.scheme,
        "host": req.host,
        "port": req.port,
        "path": req.path,
        "url": req.pretty_url,
        "http_version": req.http_version,
        "headers": _headers(req.headers),
        "body": _message_body(req),
        "stream": bool(req.stream),
        "timestamp_start": req.timestamp_start,
        "timestamp_end": req.timestamp_end,
    }


def _response_payload(flow: http.HTTPFlow) -> dict[str, Any] | None:
    resp = flow.response
    if resp is None:
        return None
    return {
        "status_code": resp.status_code,
        "reason": resp.reason,
        "http_version": resp.http_version,
        "headers": _headers(resp.headers),
        "body": _message_body(resp),
        "stream": bool(resp.stream),
        "timestamp_start": resp.timestamp_start,
        "timestamp_end": resp.timestamp_end,
    }


def _write(entry: dict[str, Any]) -> None:
    line = json.dumps(entry, ensure_ascii=True, sort_keys=True)
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def load(_: Any) -> None:
    _write(
        {
            "event": "mitmproxy.startup",
            "stream_large_bodies": ctx.options.stream_large_bodies,
            "store_streamed_bodies": ctx.options.store_streamed_bodies,
        }
    )


def response(flow: http.HTTPFlow) -> None:
    entry = {
        "event": "http.response",
        "id": flow.id,
        "client": _client_info(flow),
        "server": _server_info(flow),
        "request": _request_payload(flow),
        "response": _response_payload(flow),
    }
    _write(entry)


def error(flow: http.HTTPFlow) -> None:
    entry = {
        "event": "http.error",
        "id": flow.id,
        "client": _client_info(flow),
        "server": _server_info(flow),
        "request": _request_payload(flow),
        "error": getattr(flow.error, "msg", str(flow.error)),
    }
    _write(entry)
