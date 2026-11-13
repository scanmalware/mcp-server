from __future__ import annotations

import ast
import asyncio
import base64
import gzip
import json
import logging
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from scanmalware_mcp import server as module


class TrackedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, delay: float = 0) -> None:
        self.chunks = chunks
        self.delay = delay
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.yielded += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class ServerProtocolTests(unittest.IsolatedAsyncioTestCase):
    """Exercise tool validation and upstream requests through MCP over HTTP."""

    async def asyncSetUp(self) -> None:
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        previous_log_level = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, previous_log_level)
        self.requests: list[httpx.Request] = []
        self.upstream_status = 200
        self.upstream_timeout = False
        self.request_id = 0
        # Optional per-request override: return a Response, or None for the default.
        self.route = None

        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if self.upstream_timeout:
                raise httpx.ReadTimeout("slow upstream", request=request)
            if self.route is not None:
                routed = self.route(request)
                if routed is not None:
                    return routed
            return httpx.Response(self.upstream_status, json={"status": "ok"})

        self.upstream = httpx.AsyncClient(
            transport=httpx.MockTransport(handle),
            base_url="https://scanmalware.com",
            timeout=30,
        )
        self.addAsyncCleanup(self.upstream.aclose)
        self.patches.enter_context(patch.object(module, "_configure_logging"))
        self.patches.enter_context(patch.object(module, "_log_event"))
        self.patches.enter_context(patch.dict("os.environ", {}, clear=True))
        self.patches.enter_context(
            patch.object(
                module,
                "_get_shared_client",
                new=AsyncMock(return_value=(self.upstream, "https://scanmalware.com")),
            )
        )
        server = module.create_server(host="127.0.0.1", port=8000)
        app = server.streamable_http_app()
        ready = asyncio.Event()
        stop = asyncio.Event()

        async def run_manager() -> None:
            # AnyIO requires entry and exit in the same task; unittest runs
            # setup and cleanup in different tasks.
            async with server.session_manager.run():
                ready.set()
                await stop.wait()

        manager = asyncio.create_task(run_manager())

        async def close_manager() -> None:
            stop.set()
            await manager

        self.addAsyncCleanup(close_manager)
        await asyncio.wait_for(ready.wait(), timeout=5)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
            headers={"accept": "application/json, text/event-stream"},
        )
        self.addAsyncCleanup(self.client.aclose)
        result = await self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "regression-tests", "version": "1.0"},
            },
        )
        self.client.headers["mcp-protocol-version"] = result["protocolVersion"]
        response = await self.client.post(
            "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        response.raise_for_status()

    async def rpc(self, method: str, params: dict | None = None) -> dict:
        self.request_id += 1
        payload = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            payload["params"] = params
        response = await self.client.post("/mcp", json=payload)
        response.raise_for_status()
        self.assertNotIn("mcp-session-id", response.headers)
        if response.headers["content-type"].startswith("application/json"):
            message = response.json()
        else:
            message = next(
                json.loads(line[6:])
                for line in response.text.splitlines()
                if line.startswith("data: ")
            )
        self.assertNotIn("error", message, message)
        return message["result"]

    async def call(self, name: str, /, **arguments: object) -> dict:
        # Positional-only: get_dns_history has a tool argument called "name".
        return await self.rpc("tools/call", {"name": name, "arguments": arguments})

    async def test_crafted_traceparent_does_not_stall_the_server(self) -> None:
        # GHSA-mf5v-w3w3-f6cg / CVE-2026-126360: the SDK extracts W3C trace context from every
        # request's _meta, and opentelemetry-api 1.45.1's traceparent regex backtracks
        # quadratically on a valid prefix, a long run of spaces and a newline (which JSON allows).
        # 16 KB took 1.25 s there and 1 MB would hold the event loop for over an hour; 1.45.2
        # answers in milliseconds.
        traceparent = "00-" + "1" * 32 + "-" + "2" * 16 + "-01-" + " " * 32_000 + "\nx"
        loop = asyncio.get_running_loop()
        started = loop.time()
        await self.rpc("tools/list", {"_meta": {"traceparent": traceparent}})
        self.assertLess(loop.time() - started, 2.0)

    async def test_slow_queries_get_more_time_without_changing_other_tools(self) -> None:
        for name, args, expected in (
            ("get_favicon_stats", {}, 90),
            ("search_ocr", {"q": "phishing"}, 90),
            # ~31 s per call, measured 2026-10-07; the 30 s default timed out every time.
            ("get_jsfingerprint_similarity_counts", {"fingerprint_id": 10448358}, 90),
            # 57 s for a cold query, 0.2 s once cached.
            ("search_js_runtime_by_signature", {"signature": "fetch:4|complex"}, 90),
            # 18 s median, 27 s max and three 30 s timeouts in the week to 2026-10-08.
            ("get_technology_stats", {}, 90),
            # SMQL wildcards measured 7.6 s, CT-by-IP 6.2 s after a 503 (2026-11-12).
            ("search_smql", {"q": "domain:example.com"}, 90),
            ("get_smql_facets", {"q": "domain:example.com"}, 90),
            ("search_smql_domains", {"q": "ct_domain:*example*"}, 90),
            ("count_smql_queries", {"queries": ["domain:example.com"]}, 90),
            ("get_ct_root_domains_by_ip", {"ip_address": "192.0.2.1"}, 90),
            ("get_recent_scans", {}, 30),
            # 20-24 s until the API dropped a SELECT DISTINCT on 2026-11-13; about 1 s since.
            ("search_by_jarm", {"jarm_signature": "2ad2ad0002ad2ad00042d42d0000005d86ccb1a0567e012264097a0315d7a7"}, 30),
            ("get_dns_history", {"name": "example.com"}, 30),
        ):
            with self.subTest(tool=name):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(self.requests[-1].extensions["timeout"]["read"], expected)

    async def test_slow_query_timeout_is_configurable(self) -> None:
        with patch.dict("os.environ", {"SCANMALWARE_SLOW_QUERY_TIMEOUT_S": "75"}):
            for name, args in (("get_favicon_stats", {}), ("search_ocr", {"q": "login"})):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(self.requests[-1].extensions["timeout"]["read"], 75)

    async def test_ocr_rejects_short_queries_and_trims_valid_queries(self) -> None:
        for query in ("", "   ", " x ", " ab "):
            result = await self.call("search_ocr", q=query)
            self.assertTrue(result.get("isError"), result)
        self.assertEqual(self.requests, [])
        result = await self.call("search_ocr", q="  login  ", page=2, limit=3)
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(dict(self.requests[-1].url.params), {"q": "login", "page": "2", "limit": "3"})

    async def test_nextjs_alias_preserves_search_filters(self) -> None:
        for name in ("next.js", "Next.js", " NEXT.JS ", "nextjs"):
            with self.subTest(library=name):
                result = await self.call(
                    "search_js_fingerprint_by_library",
                    library_name=name,
                    version="14.2.35",
                    min_confidence=0.8,
                    include_cdn_only=False,
                    page=2,
                    per_page=3,
                )
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(self.requests[-1].url.path, "/api/v1/jsfingerprint/library/nextjs")
                self.assertEqual(
                    dict(self.requests[-1].url.params),
                    {"version": "14.2.35", "min_confidence": "0.8", "include_cdn_only": "false", "page": "2", "per_page": "3"},
                )
        for name in ("react", "next"):
            result = await self.call("search_js_fingerprint_by_library", library_name=name)
            self.assertFalse(result.get("isError"), result)
            self.assertEqual(self.requests[-1].url.path, f"/api/v1/jsfingerprint/library/{name}")

    async def test_filterless_searches_succeed(self) -> None:
        # Directory crawlers call every tool with its defaults; these three failed
        # that call. Two endpoints accept no filter; the pattern search needs one,
        # so it applies has_eval=true.
        for name, expected in (
            ("search_js_obfuscation", {"limit": "5"}),
            ("search_js_malware_families", {"limit": "5"}),
            ("search_js_fingerprint_patterns", {"has_eval": "true", "limit": "5"}),
        ):
            with self.subTest(tool=name):
                result = await self.call(name, limit=5)
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(dict(self.requests[-1].url.params), expected)

    async def test_pattern_search_does_not_offer_the_unsupported_websocket_filter(self) -> None:
        # The API answers 400 to has_websocket: no websocket feature is extracted.
        schema = (await self.tools())["search_js_fingerprint_patterns"]["inputSchema"]
        self.assertNotIn("has_websocket", schema["properties"])
        result = await self.call("search_js_fingerprint_patterns", has_crypto=True)
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(dict(self.requests[-1].url.params), {"has_crypto": "true", "limit": "20"})

    async def test_score_filters_use_the_api_ranges(self) -> None:
        # Agents sent percentages (70, 80) where the API takes 0-10 or 0-1 and
        # answers 422. Out-of-range values are rejected before the request.
        for name, args in (
            ("search_ai_high_risk", {"min_risk_score": 11}),
            ("search_ai_high_risk", {"min_risk_score": -1}),
            ("search_ai_high_risk", {"min_confidence": 101}),
            ("search_js_fingerprint_obfuscated", {"min_score": 40.0}),
            ("search_js_fingerprint_obfuscated", {"max_score": 1.5}),
            ("search_js_obfuscation", {"min_risk_score": 101}),
        ):
            with self.subTest(tool=name, args=args):
                result = await self.call(name, **args)
                self.assertTrue(result.get("isError"), result)
        self.assertEqual(self.requests, [])
        for name, args in (
            ("search_ai_high_risk", {"min_risk_score": 10, "min_confidence": 100}),
            ("search_ai_high_risk", {"min_risk_score": 0, "min_confidence": 0}),
            ("search_js_fingerprint_obfuscated", {"min_score": 0.4, "max_score": 1.0}),
            ("search_js_obfuscation", {"min_risk_score": 100}),
        ):
            with self.subTest(tool=name, args=args):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                for key, value in args.items():
                    self.assertEqual(self.requests[-1].url.params[key], str(value))

    async def test_explicit_false_and_zero_filters_are_forwarded(self) -> None:
        for name, args in (
            ("search_js_obfuscation", {"has_eval": False, "min_risk_score": 0}),
            ("search_js_malware_families", {"similarity_threshold": 0.0}),
            ("search_js_fingerprint_patterns", {"has_eval": False}),
        ):
            with self.subTest(tool=name):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                for key, value in args.items():
                    self.assertEqual(self.requests[-1].url.params[key], str(value).lower())

    async def test_expensive_timeout_is_not_retried(self) -> None:
        self.upstream_timeout = True
        result = await self.call("get_favicon_stats")
        self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), 1)

    async def test_semantic_search_default_and_schema_match_cross_modal_scores(self) -> None:
        tool = (await self.tools())["search_semantic"]
        threshold = tool["inputSchema"]["properties"]["threshold"]
        self.assertEqual((threshold["default"], threshold["minimum"], threshold["maximum"]), (-0.2, -1, 1))
        for args, expected in (({}, "-0.2"), ({"threshold": -0.3}, "-0.3")):
            result = await self.call("search_semantic", query="bank login", **args)
            self.assertFalse(result.get("isError"), result)
            self.assertEqual(self.requests[-1].url.params["threshold"], expected)
        sent = len(self.requests)
        for threshold in (-1.1, 1.1, "nan", "inf"):
            self.assertTrue((await self.call("search_semantic", query="login", threshold=threshold))["isError"])
        self.assertEqual(len(self.requests), sent)

    async def test_wait_deadline_covers_errors_rate_limits_and_stalled_bodies(self) -> None:
        for case in ("503", "network", "429", "stalled_body"):
            with self.subTest(case=case):
                stream = TrackedStream([b'{}'], delay=10 if case == "stalled_body" else 0)
                self.upstream_timeout = case == "network"
                self.route = lambda request: httpx.Response(
                    429 if case == "429" else 200 if case == "stalled_body" else 503,
                    headers={"retry-after": "30"}, stream=stream,
                )
                result = await asyncio.wait_for(
                    self.call("wait_for_scan", scan_id=self.SCAN_ID, timeout_s=0.03, poll_interval_s=0.1), timeout=1
                )
                self.assertFalse(result.get("isError"), result)
                self.assertTrue(result["structuredContent"]["timeout"])
                if case != "network":
                    self.assertTrue(stream.closed)

    async def test_wait_rejects_unbounded_or_invalid_timing_without_upstream_calls(self) -> None:
        for args in ({"timeout_s": 0}, {"timeout_s": -1}, {"timeout_s": 3601}, {"timeout_s": "nan"},
                     {"poll_interval_s": 0}, {"poll_interval_s": -1}, {"poll_interval_s": 61},
                     {"poll_interval_s": "inf"}):
            with self.subTest(args=args):
                self.assertTrue((await self.call("wait_for_scan", scan_id=self.SCAN_ID, **args))["isError"])
        self.assertEqual(self.requests, [])

    async def test_wait_honors_retry_after_before_recovering(self) -> None:
        times: list[float] = []

        def route(request):
            times.append(asyncio.get_running_loop().time())
            if len(times) == 1:
                return httpx.Response(429, headers={"retry-after": "0.2"}, json={"detail": "busy"})
            return httpx.Response(200, json={"status": "completed", "security_verdict": {"risk_level": "low"}})

        self.route = route
        result = await self.call("wait_for_scan", scan_id=self.SCAN_ID, timeout_s=2, poll_interval_s=0.1)
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(result["structuredContent"]["status"], "completed")
        self.assertEqual(len(times), 2)
        self.assertGreaterEqual(times[1] - times[0], 0.19)

    async def test_json_and_binary_limits_stop_reading_and_close_streams(self) -> None:
        for name, args, env_key in (
            ("get_scan_result", {"scan_id": self.SCAN_ID}, "SCANMALWARE_MAX_JSON_BYTES"),
            ("submit_scan", {"url": "https://example.com", "scan_type": "unlisted"}, "SCANMALWARE_MAX_JSON_BYTES"),
            ("get_favicon", {"scan_id": self.SCAN_ID}, "SCANMALWARE_MAX_DOWNLOAD_BYTES"),
        ):
            with self.subTest(tool=name):
                stream = TrackedStream([b'x' * 17, b'not consumed'])
                self.route = lambda request: httpx.Response(200, stream=stream)
                with patch.dict("os.environ", {env_key: "16"}):
                    result = await self.call(name, **args)
                self.assertTrue(result["isError"])
                self.assertIn("exceeded 16 bytes", result["content"][0]["text"])
                self.assertEqual(stream.yielded, 1)
                self.assertTrue(stream.closed)

    async def test_json_limit_counts_decompressed_bytes(self) -> None:
        stream = TrackedStream([gzip.compress(json.dumps({"value": "x" * 128}).encode())])
        self.route = lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)
        with patch.dict("os.environ", {"SCANMALWARE_MAX_JSON_BYTES": "64"}):
            result = await self.call("get_scan_result", scan_id=self.SCAN_ID)
        self.assertIn("exceeded 64 bytes", result["content"][0]["text"])
        self.assertTrue(stream.closed)

    async def test_error_bodies_are_truncated_without_losing_status_or_draining(self) -> None:
        for name, args in (("get_scan_result", {"scan_id": self.SCAN_ID}),
                           ("get_favicon", {"scan_id": self.SCAN_ID}),
                           ("get_netlog", {"scan_id": self.SCAN_ID}),
                           ("submit_scan", {"url": "https://example.com", "scan_type": "unlisted"})):
            with self.subTest(tool=name):
                stream = TrackedStream([b'x' * 17, b'not consumed'])
                self.route = lambda request: httpx.Response(503, stream=stream)
                with patch.dict("os.environ", {"SCANMALWARE_MAX_ERROR_BYTES": "16"}):
                    result = await self.call(name, **args)
                text = result["content"][0]["text"]
                self.assertIn("ScanMalware API error 503", text)
                self.assertIn("[truncated]", text)
                self.assertEqual(stream.yielded, 1)
                self.assertTrue(stream.closed)

    async def test_resource_templates_preserve_bytes_and_mime(self) -> None:
        self.route = lambda request: httpx.Response(200, content=b'fixture')
        for uri, mime in ((f"scanmalware://screenshot/{self.SCAN_ID}.png", "image/png"),
                          (f"scanmalware://certificate/{self.SCAN_ID}.pem", "application/x-pem-file"),
                          # The API serves the capture as .pcap.gz (application/gzip).
                          (f"scanmalware://pcap/{self.SCAN_ID}.pcap", "application/gzip"),
                          ("scanmalware://rss/rss.xml", "application/rss+xml")):
            with self.subTest(uri=uri):
                content = (await self.rpc("resources/read", {"uri": uri}))["contents"][0]
                self.assertEqual(content["mimeType"], mime)
                self.assertEqual(base64.b64decode(content["blob"]), b'fixture')

    async def test_scan_visibility_is_preserved_and_invalid_values_are_rejected(self) -> None:
        for visibility in ("public", "unlisted", "private"):
            result = await self.call("submit_scan", url="https://example.com", scan_type=visibility)
            self.assertFalse(result.get("isError"), result)
            self.assertEqual(json.loads(self.requests[-1].content)["scan_type"], visibility)
        result = await self.call("submit_scan", url="https://example.com", scan_type="privte")
        self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), 3)

    async def test_private_auth_error_does_not_downgrade_or_retry(self) -> None:
        self.upstream_status = 401
        result = await self.call("submit_scan", url="https://example.com", scan_type="private")
        self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(json.loads(self.requests[0].content)["scan_type"], "private")

    SCAN_ID = "ff26242d-0a9e-405d-a03d-3554cc90b682"

    @staticmethod
    def streamed(status: int, payload: dict) -> httpx.Response:
        # An unread body, as the real upstream delivers it. httpx.Response(json=...)
        # is pre-read, which hid the ResponseNotRead crash from these tests.
        return httpx.Response(
            status,
            headers={"content-type": "application/json"},
            stream=httpx.ByteStream(json.dumps(payload).encode()),
        )

    async def tools(self) -> dict[str, dict]:
        listed = await self.rpc("tools/list", {})
        return {tool["name"]: tool for tool in listed["tools"]}

    async def test_missing_favicon_and_netlog_are_answers_not_errors(self) -> None:
        # Both endpoints are streamed. Reading the error body of a streamed 404
        # used to raise httpx.ResponseNotRead, so a scan without a favicon or
        # NetLog produced an internal error instead of an answer.
        self.route = lambda request: self.streamed(404, {"error": "Not Found", "status_code": 404})
        favicon = await self.call("get_favicon", scan_id=self.SCAN_ID)
        self.assertFalse(favicon.get("isError"), favicon)
        self.assertEqual(favicon["structuredContent"]["found"], False)
        netlog = await self.call("get_netlog", scan_id=self.SCAN_ID)
        self.assertFalse(netlog.get("isError"), netlog)
        self.assertEqual(netlog["structuredContent"]["available"], False)

    async def test_streamed_upstream_errors_report_the_api_error(self) -> None:
        self.route = lambda request: self.streamed(500, {"error": "upstream broke"})
        for name in ("get_favicon", "get_netlog"):
            with self.subTest(tool=name):
                result = await self.call(name, scan_id=self.SCAN_ID)
                self.assertTrue(result.get("isError"), result)
                text = result["content"][0]["text"]
                self.assertIn("ScanMalware API error 500", text)
                self.assertIn("upstream broke", text)
                self.assertNotIn("read()", text)

    async def test_present_favicon_is_returned(self) -> None:
        png = b"\x89PNG\r\n\x1a\nfavicon"
        self.route = lambda request: httpx.Response(
            200,
            content=png,
            headers={"content-type": "image/png", "X-Favicon-MD5": "51b99ddea2eddb0ff44673bef2faad5f",
                     "X-Favicon-MMH3": "-1269865183"},
        )
        result = await self.call("get_favicon", scan_id=self.SCAN_ID)
        self.assertFalse(result.get("isError"), result)
        favicon = result["structuredContent"]
        self.assertEqual(favicon["found"], True)
        self.assertEqual(favicon["size_bytes"], len(png))
        # The hashes favicon search indexes are the original file's, sent as headers; a hash of
        # the served copy changed on every request and matched nothing.
        self.assertEqual(favicon["md5"], "51b99ddea2eddb0ff44673bef2faad5f")
        self.assertEqual(favicon["mmh3"], -1269865183)
        self.assertEqual(len(favicon["sha256"]), 64)

    async def test_favicon_without_hash_headers_reports_no_hashes(self) -> None:
        self.route = lambda request: httpx.Response(200, content=b"\x89PNG", headers={"content-type": "image/png"})
        favicon = (await self.call("get_favicon", scan_id=self.SCAN_ID))["structuredContent"]
        self.assertIsNone(favicon["md5"])
        self.assertIsNone(favicon["mmh3"])

    async def test_text_blocks_are_compact_json_mirroring_structured_content(self) -> None:
        data = {"results": [{"scan_id": "a", "title": "Bank \u00e5\u00e4\u00f6 login"}], "pagination": {"page": 1}}
        self.route = lambda request: httpx.Response(200, json=data)
        result = await self.call("get_recent_scans")
        [block] = result["content"]
        self.assertNotIn("\n", block["text"])
        self.assertIn("Bank \u00e5\u00e4\u00f6 login", block["text"])
        self.assertEqual(json.loads(block["text"]), result["structuredContent"])
        self.assertEqual(result["structuredContent"], data)
        # A list result keeps the SDK's layout: one block per item, wrapped structured content.
        rows = [{"cpe": "cpe:2.3:a:x:y"}, {"cpe": "cpe:2.3:a:z:w"}]
        self.route = lambda request: httpx.Response(200, json=rows)
        result = await self.call("get_cpe_by_scan", scan_id=self.SCAN_ID)
        self.assertEqual([json.loads(block["text"]) for block in result["content"]], rows)
        self.assertTrue(all("\n" not in block["text"] for block in result["content"]))
        self.assertEqual(result["structuredContent"], {"result": rows})

    async def test_fingerprint_id_must_be_positive_before_any_request(self) -> None:
        for name in ("get_jsfingerprint", "get_jsfingerprint_similar", "get_jsfingerprint_similarity_counts",
                     "get_jsfingerprint_source"):
            with self.subTest(tool=name):
                result = await self.call(name, fingerprint_id=0)
                self.assertTrue(result.get("isError"), result)
                text = result["content"][0]["text"]
                # The schema's minimum is enforced before the tool runs.
                self.assertIn("fingerprint_id", text)
                self.assertIn("greater than or equal to 1", text)
        self.assertEqual(self.requests, [])

    async def test_per_page_errors_name_per_page(self) -> None:
        for name, args in (("search_js_fingerprint_obfuscated", {}),
                           ("search_js_fingerprint_by_bundler", {"bundler_type": "webpack"}),
                           ("search_js_fingerprint_by_library", {"library_name": "react"})):
            with self.subTest(tool=name):
                result = await self.call(name, per_page=0, **args)
                self.assertTrue(result.get("isError"), result)
                text = result["content"][0]["text"]
                self.assertIn("per_page", text)
                self.assertIn("greater than or equal to 1", text)
        self.assertEqual(self.requests, [])

    async def test_scan_date_must_be_a_calendar_date(self) -> None:
        for value in ("2026-13-45", "2026-02-30", "yesterday", "2026-1-1", ""):
            with self.subTest(scan_date=value):
                result = await self.call("get_capabilities_by_date", scan_date=value)
                self.assertTrue(result.get("isError"), result)
                self.assertIn("scan_date must be a calendar date", result["content"][0]["text"])
        self.assertEqual(self.requests, [])
        result = await self.call("get_capabilities_by_date", scan_date=" 2026-11-01 ")
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(self.requests[-1].url.params["scan_date"], "2026-11-01")

    async def test_library_stats_are_limited_by_the_api(self) -> None:
        # Unpaged, the API listed 18,293 libraries (3.1 MB; 9.4 MB on the MCP wire).
        await self.call("get_jsfingerprint_library_stats")
        self.assertEqual(dict(self.requests[-1].url.params), {"limit": "100", "versions_limit": "10"})
        await self.call("get_jsfingerprint_library_stats", limit=5, versions_limit=0, min_count=50)
        self.assertEqual(dict(self.requests[-1].url.params), {"limit": "5", "versions_limit": "0", "min_count": "50"})
        sent = len(self.requests)
        for args in ({"limit": 0}, {"limit": 1001}, {"versions_limit": -1}):
            with self.subTest(args=args):
                self.assertTrue((await self.call("get_jsfingerprint_library_stats", **args)).get("isError"))
        self.assertEqual(len(self.requests), sent)

    async def test_scan_result_is_compact_unless_asked(self) -> None:
        await self.call("get_scan_result", scan_id=self.SCAN_ID)
        self.assertEqual(dict(self.requests[-1].url.params), {"compact": "true"})
        await self.call("get_scan_result", scan_id=self.SCAN_ID, compact=False)
        self.assertEqual(dict(self.requests[-1].url.params), {})

    async def test_js_fingerprints_are_paged(self) -> None:
        await self.call("get_js_fingerprints", scan_id=self.SCAN_ID)
        self.assertEqual(dict(self.requests[-1].url.params), {"limit": "20", "offset": "0"})
        await self.call("get_js_fingerprints", scan_id=self.SCAN_ID, limit=100, offset=40, include_http_headers=False)
        self.assertEqual(dict(self.requests[-1].url.params),
                         {"limit": "100", "offset": "40", "include_http_headers": "false"})
        sent = len(self.requests)
        for args in ({"limit": 0}, {"limit": 101}, {"offset": -1}):
            with self.subTest(args=args):
                self.assertTrue((await self.call("get_js_fingerprints", scan_id=self.SCAN_ID, **args)).get("isError"))
        self.assertEqual(len(self.requests), sent)

    async def test_paging_bounds_are_in_the_schema_and_defaults_satisfy_them(self) -> None:
        # The bounds were only in the descriptions, so a client could not check a call before
        # making it. Every limit, per_page, page, offset and fingerprint_id now declares them.
        tools = (await self.rpc("tools/list", {}))["tools"]

        def bounds(spec: dict) -> dict:
            options = [spec, *spec.get("anyOf", [])]
            return {key: option[key] for option in options for key in ("minimum", "maximum") if key in option}

        checked = 0
        for tool in tools:
            for name, spec in tool["inputSchema"].get("properties", {}).items():
                if name not in {"limit", "per_page", "page", "offset", "fingerprint_id", "versions_limit"}:
                    continue
                with self.subTest(tool=tool["name"], argument=name):
                    found = bounds(spec)
                    self.assertIn("minimum", found)
                    if name in {"limit", "per_page", "versions_limit"}:
                        self.assertIn("maximum", found)
                    default = spec.get("default")
                    if isinstance(default, int):
                        self.assertGreaterEqual(default, found["minimum"])
                        self.assertLessEqual(default, found.get("maximum", default))
                    checked += 1
        self.assertGreater(checked, 120)
        recent = next(tool for tool in tools if tool["name"] == "get_recent_scans")["inputSchema"]["properties"]
        self.assertEqual((recent["limit"]["minimum"], recent["limit"]["maximum"], recent["page"]["minimum"]), (1, 100, 1))

    async def test_signature_is_sent_as_one_encoded_path_segment(self) -> None:
        result = await self.call("search_js_runtime_by_signature", signature="setTimeout:30|fetch:4/x?y#z")
        self.assertFalse(result.get("isError"), result)
        request = self.requests[-1]
        self.assertTrue(
            request.url.raw_path.startswith(
                b"/api/v1/js-fingerprinter2/search/signature/setTimeout%3A30%7Cfetch%3A4%2Fx%3Fy%23z?"
            ),
            request.url.raw_path,
        )
        self.assertEqual(dict(request.url.params), {"limit": "20"})
        result = await self.call("search_js_runtime_by_signature", signature="   ")
        self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), 1)

    async def test_scan_visibility_must_be_chosen(self) -> None:
        schema = (await self.tools())["submit_scan"]["inputSchema"]
        self.assertIn("scan_type", schema["required"])
        self.assertNotIn("default", schema["properties"]["scan_type"])
        result = await self.call("submit_scan", url="https://example.com")
        self.assertTrue(result.get("isError"), result)
        self.assertEqual(self.requests, [])

    async def test_scan_report_only_casts_the_two_captcha_free_votes(self) -> None:
        tool = (await self.tools())["submit_scan_report"]
        properties = tool["inputSchema"]["properties"]
        self.assertEqual(set(properties), {"scan_id", "report_type", "report_details"})
        self.assertEqual(set(properties["report_type"]["enum"]), {"positive_feedback", "malware"})
        for vote in ("positive_feedback", "malware"):
            result = await self.call("submit_scan_report", scan_id=self.SCAN_ID, report_type=vote)
            self.assertFalse(result.get("isError"), result)
            request = self.requests[-1]
            self.assertEqual(
                json.loads(request.content),
                {"scan_id": self.SCAN_ID, "report_type": vote, "skip_captcha": True},
            )
            self.assertNotIn("x-forwarded-for", request.headers)
            self.assertNotIn("x-real-ip", request.headers)
        sent = len(self.requests)
        for args in (
            {"report_type": "phishing"},
            {"report_type": "malware", "report_details": "x" * 1001},
        ):
            with self.subTest(args=args):
                result = await self.call("submit_scan_report", scan_id=self.SCAN_ID, **args)
                self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), sent)
        # The SDK ignores arguments a tool does not declare, so a client still
        # sending the removed IP parameters gets a vote without the spoofed header.
        result = await self.call(
            "submit_scan_report", scan_id=self.SCAN_ID, report_type="malware", x_forwarded_for="203.0.113.9"
        )
        self.assertFalse(result.get("isError"), result)
        self.assertNotIn("x-forwarded-for", self.requests[-1].headers)
        self.assertNotIn("203.0.113.9", self.requests[-1].content.decode())

    async def test_every_tool_explains_itself(self) -> None:
        # Directory review (OpenAI) requires each description to explain what the
        # tool does, when it is useful and its limits. One-line stubs such as
        # "Get OCR stats." failed that bar for most of the then 128 tools.
        tools = await self.tools()
        self.assertEqual(len(tools), 145)
        for name, tool in tools.items():
            with self.subTest(tool=name):
                self.assertGreaterEqual(len(tool.get("description") or ""), 60)

    async def test_every_argument_explains_itself(self) -> None:
        # Agents choose and fill tools from the argument descriptions in inputSchema, and
        # directory scores count them; before 0.2.1 none of the 335 arguments had one.
        tools = await self.tools()
        for name, tool in tools.items():
            for arg, prop in (tool["inputSchema"].get("properties") or {}).items():
                description = prop.get("description") or ""
                with self.subTest(tool=name, argument=arg):
                    self.assertGreaterEqual(len(description), 15)
                    for other in tools:
                        if other != name:
                            self.assertNotRegex(description, rf"\b{other}\b")

    async def test_server_info_names_its_icon_and_website(self) -> None:
        info = (
            await self.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "regression-tests", "version": "1.0"},
                },
            )
        )["serverInfo"]
        self.assertEqual(info["version"], module.__version__)
        self.assertEqual(info["websiteUrl"], "https://mcp.scanmalware.com")
        self.assertEqual(
            info["icons"], [{"src": "https://mcp.scanmalware.com/icon.png", "mimeType": "image/png", "sizes": ["512x512"]}]
        )
        # server.json and the icon file are checked against the repo in
        # tests/maintenance/test_release_metadata.py: this suite runs inside the image.

    async def test_descriptions_do_not_point_at_other_tools(self) -> None:
        # Directory review rejects descriptions that instruct the model to call
        # other tools. A tool may describe its own inputs, not route the model.
        tools = await self.tools()
        for name, tool in tools.items():
            description = tool.get("description") or ""
            for other in tools:
                if other != name:
                    with self.subTest(tool=name, mentions=other):
                        self.assertNotRegex(description, rf"\b{other}\b")

    async def test_titles_use_plain_words(self) -> None:
        # OpenAI's directory scan flagged "Get Netlog" and the "JS Fingerprinter2"
        # titles as names that do not communicate their purpose, and a later scan
        # flagged the *_js_fingerprinter2* tool names themselves. Titles and names
        # are what users and reviewers see, so internal service names stay out.
        tools = await self.tools()
        for name, tool in tools.items():
            title = tool.get("title") or ""
            with self.subTest(tool=name, title=title):
                self.assertNotRegex(title, r"(?i)netlog|fingerprinter")
                self.assertNotRegex(name, r"fingerprinter")

    async def test_wait_for_scan_marks_a_pending_verdict(self) -> None:
        # The verdict follows "completed" by 19-73 s and never comes for a failed
        # scan. An unmarked empty verdict was reported by ChatGPT as a verdict
        # based on risk score 0.
        verdict = {"verdict": "Low Risk", "risk_level": "low", "confidence": 77}
        for statuses, final_verdict, pending in (
            (["processing", "completed"], {}, True),
            (["queued", "completed"], verdict, False),
            (["processing", "failed"], {}, False),
        ):
            with self.subTest(statuses=statuses, verdict=bool(final_verdict)):
                replies = iter(statuses)
                before = len(self.requests)

                def route(request: httpx.Request, replies=replies, final_verdict=final_verdict):
                    status = next(replies)
                    body = {"scan_id": self.SCAN_ID, "status": status, "risk_score": 0}
                    body["security_verdict"] = final_verdict if status != "processing" else {}
                    return httpx.Response(200, json=body)

                self.route = route
                result = await self.call("wait_for_scan", scan_id=self.SCAN_ID, poll_interval_s=0.1)
                self.assertFalse(result.get("isError"), result)
                summary = result["structuredContent"]
                self.assertEqual(summary["status"], statuses[-1])
                self.assertIs(summary["verdict_pending"], pending)
                self.assertEqual("verdict_note" in summary, pending)
                self.assertEqual(summary["security_verdict"], final_verdict)
                # Returns on the first terminal status: no extra polling for the verdict.
                self.assertEqual(len(self.requests) - before, len(statuses))

    async def test_calls_are_traced_upstream_and_in_the_log(self) -> None:
        # The call ID joins mcp.log to mitmproxy's log (which records request
        # headers), and the upstream paths in mcp.log show where a crafted
        # argument actually went, long after the proxy log has rotated.
        result = await self.call("get_domain_stats", domain="example.com/../../platform/stats")
        self.assertFalse(result.get("isError"), result)
        call_id = self.requests[-1].headers["x-mcp-call-id"]
        start = [e for e in self.logged("mcp.tool.start") if e["tool"] == "get_domain_stats"][-1]
        end = [e for e in self.logged("mcp.tool.end") if e["tool"] == "get_domain_stats"][-1]
        self.assertEqual(start["call_id"], call_id)
        self.assertEqual(end["call_id"], call_id)
        self.assertEqual(
            end["upstream"], ["GET /api/v1/domain/stats/example.com%2F..%2F..%2Fplatform%2Fstats 200"]
        )
        self.assertEqual(end["upstream_total"], 1)
        # A different call gets a different ID.
        await self.call("get_recent_scans")
        self.assertNotEqual(self.requests[-1].headers["x-mcp-call-id"], call_id)

    async def test_polling_and_failed_upstream_calls_are_summarised(self) -> None:
        replies = iter(["processing", "processing", "completed"])
        self.route = lambda request: httpx.Response(
            200, json={"scan_id": self.SCAN_ID, "status": next(replies), "security_verdict": {}}
        )
        await self.call("wait_for_scan", scan_id=self.SCAN_ID, poll_interval_s=0.1)
        end = [e for e in self.logged("mcp.tool.end") if e["tool"] == "wait_for_scan"][-1]
        self.assertEqual(end["upstream"], [f"GET /api/v1/scan/{self.SCAN_ID}/summary 200 x3"])
        self.assertEqual(end["upstream_total"], 3)
        self.route = None
        self.upstream_timeout = True
        await self.call("get_favicon_stats")
        error = [e for e in self.logged("mcp.tool.error") if e["tool"] == "get_favicon_stats"][-1]
        self.assertEqual(error["upstream"], ["GET /api/v1/favicon/stats error:ReadTimeout"])

    async def test_scan_outcomes_and_internal_targets_are_logged(self) -> None:
        # The redirect-to-127.0.0.1 scans of 2026-10-02 were only provable from
        # the raw HTTP log, which rotates out after about a week.
        def summary(final_url: str, redirects: list[dict] | None = None) -> httpx.Response:
            body = {
                "scan_id": self.SCAN_ID,
                "url": "https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%2F",
                "final_url": final_url,
                "status": "completed",
                "redirect_count": 1,
                "risk_score": 0,
                "security_verdict": {"risk_level": "low"},
            }
            if redirects is not None:
                body["redirects"] = redirects
            return httpx.Response(200, json=body)

        self.route = lambda request: summary("http://127.0.0.1/")
        await self.call("get_scan_summary", scan_id=self.SCAN_ID)
        outcome = self.logged("mcp.scan.outcome")[-1]
        self.assertEqual(
            (outcome["tool"], outcome["final_url"], outcome["status"], outcome["risk_level"]),
            ("get_scan_summary", "http://127.0.0.1/", "completed", "low"),
        )
        warning = self.logged("mcp.scan.internal_target")[-1]
        self.assertEqual(warning["internal_hosts"], ["127.0.0.1"])
        self.assertEqual(warning["call_id"], outcome["call_id"])
        # A redirect through the metadata address is caught even if the final URL is public.
        self.route = lambda request: summary(
            "https://example.com/", [{"from": "https://x.test/", "to": "http://169.254.169.254/"}]
        )
        await self.call("get_scan_result", scan_id=self.SCAN_ID)
        self.assertEqual(self.logged("mcp.scan.internal_target")[-1]["internal_hosts"], ["169.254.169.254"])
        warnings = len(self.logged("mcp.scan.internal_target"))
        self.route = lambda request: summary("https://example.com/")
        await self.call("get_scan_summary", scan_id=self.SCAN_ID)
        self.assertEqual(len(self.logged("mcp.scan.internal_target")), warnings)

    async def test_submissions_log_their_target_and_visibility(self) -> None:
        self.route = lambda request: httpx.Response(200, json={"scan_id": self.SCAN_ID, "status": "queued"})
        await self.call("submit_scan", url="https://example.com/login", scan_type="unlisted")
        outcome = self.logged("mcp.scan.outcome")[-1]
        self.assertEqual(
            (outcome["tool"], outcome["scan_id"], outcome["url"], outcome["scan_type"], outcome["status"]),
            ("submit_scan", self.SCAN_ID, "https://example.com/login", "unlisted", "queued"),
        )

    async def test_free_text_path_values_stay_in_their_segment(self) -> None:
        # Raw interpolation let httpx resolve "..": this domain reached
        # /api/v1/domain/platform/stats in production on 2026-10-02.
        for name, args, raw_path in (
            (
                "get_domain_stats",
                {"domain": "example.com/../../platform/stats"},
                b"/api/v1/domain/stats/example.com%2F..%2F..%2Fplatform%2Fstats",
            ),
            (
                "search_by_registrar",
                {"registrar_name": "GoDaddy.com, LLC"},
                b"/api/v1/registrar/search/GoDaddy.com%2C%20LLC",
            ),
            ("search_cpe", {"cpe_pattern": "cpe:2.3:a:jquery:jquery"}, b"/api/v1/cpe/search/cpe%3A2.3%3Aa%3Ajquery%3Ajquery"),
            (
                "search_jsfingerprints_by_library_version",
                {"library": "jquery/../..", "version": "3.7.1"},
                b"/api/v1/jsfingerprints/search/library/jquery%2F..%2F../version/3.7.1",
            ),
            ("search_tracking_key", {"tracker_type": "google_analytics", "key": "UA-1?x#y"}, b"/api/v1/tracking-keys/google_analytics/UA-1%3Fx%23y"),
        ):
            with self.subTest(tool=name):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                self.assertEqual(self.requests[-1].url.raw_path.split(b"?")[0], raw_path)
        sent = len(self.requests)
        for value in ("..", ".", "  "):
            with self.subTest(domain=value):
                result = await self.call("get_domain_stats", domain=value)
                self.assertTrue(result.get("isError"), result)
        self.assertEqual(len(self.requests), sent)

    async def test_endpoint_tools_send_the_documented_request(self) -> None:
        # Paths and query parameters as the live OpenAPI spec gives them on
        # 2026-11-12. The YARA tools moved to /hunting-rules/* when /yara/* left
        # the spec, and the report list behind get_scan_reports began answering 401.
        scan = self.SCAN_ID
        sha256 = "78714F6F57C5177201837CE7A6185A2B2BB00A074883FC6CF03B8ADE192A20BA"
        for name, args, path, params in (
            ("get_scan_reports", {"scan_id": scan}, f"/api/v1/reports/{scan}/counts", {}),
            ("get_yara_matches", {"scan_id": scan}, f"/api/v1/hunting-rules/scan/{scan}", {}),
            ("get_yara_by_scan", {"scan_id": scan}, f"/api/v1/hunting-rules/{scan}", {}),
            ("get_yara_stats", {}, "/api/v1/hunting-rules/stats", {}),
            (
                "get_recent_yara_threats",
                {"hours": 168},
                "/api/v1/hunting-rules/threats/recent",
                {"hours": "168", "limit": "20"},
            ),
            (
                "search_smql",
                {"q": "  domain:paypal.com  "},
                "/api/v1/search/smql",
                {"q": "domain:paypal.com", "page": "1", "limit": "20", "sort": "newest"},
            ),
            (
                "search_smql",
                {"q": "title:login", "sort": "oldest", "count_only": True, "page": 1000},
                "/api/v1/search/smql",
                {"q": "title:login", "page": "1000", "limit": "20", "sort": "oldest", "count_only": "true"},
            ),
            (
                "get_smql_facets",
                {"q": "domain:paypal.com", "fields": "primary_asn,country", "size": 25, "sample": 100},
                "/api/v1/search/smql/facets",
                {"q": "domain:paypal.com", "fields": "primary_asn,country", "size": "25", "sample": "100"},
            ),
            (
                "search_smql_domains",
                {"q": "ct_ip:192.0.2.0/24", "limit": 500, "cursor": "example.org"},
                "/api/v1/search/smql/domains",
                {"q": "ct_ip:192.0.2.0/24", "limit": "500", "cursor": "example.org"},
            ),
            ("get_scan_pivot_values", {"scan_id": scan}, f"/api/v1/scans/{scan}/pivot-values", {}),
            (
                "get_ct_root_domains_by_ip",
                {"ip_address": "192.0.2.1", "window": "extended"},
                "/api/v1/ct/ip/192.0.2.1/domains",
                {"window": "extended", "limit": "100"},
            ),
            ("get_dns_history", {"name": " paypal.com "}, "/api/v1/dns/history/paypal.com", {"limit": "100"}),
            # A host address inside the network is reduced to the network; the
            # "/" stays in its segment.
            (
                "search_reverse_dns",
                {"kind": "ip", "value": "192.0.2.7/24"},
                "/api/v1/dns/reverse/ip/192.0.2.0%2F24",
                {"limit": "100"},
            ),
            (
                "search_reverse_dns",
                {"kind": "ip", "value": "2001:db8::1/128", "limit": 500},
                "/api/v1/dns/reverse/ip/2001%3Adb8%3A%3A1",
                {"limit": "500"},
            ),
            (
                "search_reverse_dns",
                {"kind": "verification", "value": "google-site-verification=abc"},
                "/api/v1/dns/reverse/verification/google-site-verification%3Dabc",
                {"limit": "100"},
            ),
            ("search_reverse_dns", {"kind": "ns", "value": "ns1.example.net"}, "/api/v1/dns/reverse/ns/ns1.example.net", {"limit": "100"}),
            ("get_scan_dns", {"scan_id": scan}, f"/api/v1/dns/scan/{scan}", {}),
            (
                "get_domain_hosts",
                {"domain": "paypal.com", "sources": ["observed", "static", "observed"], "subdomains_only": True},
                "/api/v1/hosts/paypal.com",
                {"sources": "observed,static", "subdomains_only": "true", "max_scans": "200", "limit": "500"},
            ),
            ("get_domain_hosts", {"domain": "paypal.com"}, "/api/v1/hosts/paypal.com", {"max_scans": "200", "limit": "500"}),
            ("get_scan_deobfuscation", {"scan_id": scan}, f"/api/v1/scans/{scan}/deobfuscation", {}),
            ("get_script_deobfuscation", {"fingerprint_id": 17144532}, "/api/v1/jsfingerprints/17144532/deobfuscation", {}),
            (
                "get_script_decoded_source",
                {"fingerprint_id": 17144532},
                "/api/v1/jsfingerprints/17144532/decoded-source",
                {"part": "decoded-0"},
            ),
            (
                "get_script_decoded_source",
                {"fingerprint_id": 17144532, "part": "strings"},
                "/api/v1/jsfingerprints/17144532/decoded-source",
                {"part": "strings"},
            ),
            ("get_script_command_literals", {"fingerprint_id": 17144532}, "/api/v1/jsfingerprints/17144532/command-literals", {}),
            ("get_file_analysis", {"sha256": sha256}, f"/api/v1/files/{sha256.lower()}", {}),
        ):
            with self.subTest(tool=name, args=args):
                result = await self.call(name, **args)
                self.assertFalse(result.get("isError"), result)
                request = self.requests[-1]
                self.assertEqual(request.method, "GET")
                self.assertEqual(request.url.raw_path.split(b"?")[0], path.encode())
                self.assertEqual(dict(request.url.params), params)

    async def test_query_counts_and_scan_graph_post_their_body(self) -> None:
        result = await self.call("count_smql_queries", queries=[" domain:example.com ", "title:login"], sites=True)
        self.assertFalse(result.get("isError"), result)
        request = self.requests[-1]
        self.assertEqual((request.method, request.url.path), ("POST", "/api/v1/search/smql/counts"))
        self.assertEqual(json.loads(request.content), {"queries": ["domain:example.com", "title:login"], "sites": True})
        await self.call("count_smql_queries", queries=["domain:example.com"])
        self.assertEqual(json.loads(self.requests[-1].content), {"queries": ["domain:example.com"]})

        def graph(request: httpx.Request) -> httpx.Response:
            # 20 real scans measured 1.47 MB, nearly all of it `pv`.
            return httpx.Response(
                200,
                json={
                    "scans": [
                        {
                            "scan_id": self.SCAN_ID,
                            "title": "Example",
                            "favicon": "data:image/png;base64,AAAA",
                            "pv": {"resources": [{"sha256": "a" * 64}]},
                        }
                    ],
                    "missing": [],
                },
            )

        self.route = graph
        result = await self.call("get_scan_graph", scan_ids=[self.SCAN_ID.upper(), self.SCAN_ID])
        self.assertFalse(result.get("isError"), result)
        request = self.requests[-1]
        self.assertEqual((request.method, request.url.path), ("POST", "/api/v1/graph/scans"))
        self.assertEqual(json.loads(request.content), {"scan_ids": [self.SCAN_ID]})
        self.assertEqual(result["structuredContent"]["scans"], [{"scan_id": self.SCAN_ID, "title": "Example"}])
        result = await self.call("get_scan_graph", scan_ids=[self.SCAN_ID], include_pivot_values=True)
        entry = result["structuredContent"]["scans"][0]
        self.assertEqual(entry["pv"], {"resources": [{"sha256": "a" * 64}]})
        self.assertNotIn("favicon", entry)

    async def test_smql_filters_list_names_until_a_category_is_chosen(self) -> None:
        catalog = {
            "filters": {
                "Core": [{"name": "url", "type": "text", "examples": ["paypal.com"]}],
                "DNS": [{"name": "dns_ip", "type": "text"}, {"name": "dns_mx", "type": "text"}],
            },
            "has_checks": [{"name": "malware", "description": "Malware detected by ClamAV"}],
            "unavailable": [],
            "syntax": {"filter": "field:value"},
        }
        self.route = lambda request: httpx.Response(200, json=catalog)
        result = await self.call("get_smql_filters")
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(
            result["structuredContent"],
            {
                "syntax": {"filter": "field:value"},
                "has_checks": ["malware"],
                "categories": {"Core": ["url"], "DNS": ["dns_ip", "dns_mx"]},
                "unavailable": [],
            },
        )
        result = await self.call("get_smql_filters", category=" dns ")
        self.assertEqual(
            result["structuredContent"],
            {"category": "DNS", "filters": catalog["filters"]["DNS"], "syntax": {"filter": "field:value"}},
        )
        result = await self.call("get_smql_filters", category="Whois")
        self.assertTrue(result.get("isError"), result)
        self.assertIn("Core, DNS", json.dumps(result))

    async def test_endpoint_tools_reject_bad_input_without_a_request(self) -> None:
        scan = self.SCAN_ID
        for name, args in (
            ("search_smql", {"q": "   "}),
            ("search_smql", {"q": "x" * 2001}),
            ("search_smql", {"q": "domain:a.com", "page": 1001}),
            ("search_smql", {"q": "domain:a.com", "limit": 101}),
            ("search_smql", {"q": "domain:a.com", "sort": "relevance"}),
            ("get_smql_facets", {"q": "domain:a.com", "size": 26}),
            ("get_smql_facets", {"q": "domain:a.com", "sample": 99}),
            ("get_smql_facets", {"q": "domain:a.com", "fields": "f" * 401}),
            ("search_smql_domains", {"q": "ct_ip:192.0.2.1", "limit": 501}),
            ("search_smql_domains", {"q": "ct_ip:192.0.2.1", "cursor": "c" * 254}),
            ("count_smql_queries", {"queries": []}),
            ("count_smql_queries", {"queries": ["domain:a.com"] * 26}),
            ("count_smql_queries", {"queries": ["domain:a.com", " "]}),
            ("get_scan_graph", {"scan_ids": []}),
            ("get_scan_graph", {"scan_ids": [scan] * 21}),
            ("get_scan_graph", {"scan_ids": [scan, "../recent"]}),
            ("get_scan_pivot_values", {"scan_id": "../recent"}),
            ("get_ct_root_domains_by_ip", {"ip_address": "example.com"}),
            ("get_ct_root_domains_by_ip", {"ip_address": "192.0.2.1", "limit": 501}),
            ("get_ct_root_domains_by_ip", {"ip_address": "192.0.2.1", "window": "all"}),
            ("get_dns_history", {"name": ".."}),
            ("get_dns_history", {"name": "example.com", "limit": 501}),
            ("search_reverse_dns", {"kind": "ip", "value": "example.com"}),
            ("search_reverse_dns", {"kind": "ip", "value": "10.0.0.0/8"}),
            ("search_reverse_dns", {"kind": "ip", "value": "2001:db8::/31"}),
            ("search_reverse_dns", {"kind": "txt", "value": "v=spf1"}),
            ("search_reverse_dns", {"kind": "ns", "value": " "}),
            ("get_scan_dns", {"scan_id": "../recent"}),
            ("get_domain_hosts", {"domain": "example.com", "limit": 10001}),
            ("get_domain_hosts", {"domain": "example.com", "max_scans": 0}),
            ("get_domain_hosts", {"domain": "example.com", "sources": ["stream"]}),
            ("get_domain_hosts", {"domain": ".."}),
            ("get_script_decoded_source", {"fingerprint_id": 1, "part": "source"}),
            ("get_script_decoded_source", {"fingerprint_id": 1, "part": "decoded-0/../x"}),
            ("get_script_deobfuscation", {"fingerprint_id": 0}),
            ("get_script_command_literals", {"fingerprint_id": -1}),
            ("get_file_analysis", {"sha256": "abc"}),
            ("get_file_analysis", {"sha256": "g" * 64}),
            ("get_recent_yara_threats", {"hours": 169}),
            ("get_recent_yara_threats", {"hours": 0}),
        ):
            with self.subTest(tool=name, args={k: str(v)[:40] for k, v in args.items()}):
                result = await self.call(name, **args)
                self.assertTrue(result.get("isError"), result)
        self.assertEqual(self.requests, [])

    async def raw_post(self, payload: dict, accept: str | None) -> httpx.Response:
        request = self.client.build_request("POST", "/mcp", json=payload)
        if accept is None:
            del request.headers["accept"]
        else:
            request.headers["accept"] = accept
        return await self.client.send(request)

    async def test_wildcard_accept_headers_are_served(self) -> None:
        # mcp 1.30 wanted both literal types, so these got 406 although they
        # accept both: 942 POSTs in one week from one aiohttp client alone.
        listing = {"jsonrpc": "2.0", "id": 99, "method": "tools/list"}
        for accept in ("*/*", "application/*, text/*", "*/*;q=0.8"):
            with self.subTest(accept=accept):
                response = await self.raw_post(listing, accept)
                self.assertEqual(response.status_code, 200, response.text)
        # Headers that exclude one of the types are still refused.
        for accept in ("application/json", "text/event-stream", "text/html"):
            with self.subTest(accept=accept):
                response = await self.raw_post(listing, accept)
                self.assertEqual(response.status_code, 406, response.text)

    async def test_get_offers_no_stream(self) -> None:
        # mcp 2.x accepts */* on GET and holds the stream open until the client
        # leaves; the server sends nothing on it, so it answers 405 instead.
        for accept in ("*/*", "text/event-stream", "text/html,application/xhtml+xml,*/*;q=0.8"):
            with self.subTest(accept=accept):
                response = await asyncio.wait_for(self.client.get("/mcp", headers={"accept": accept}), timeout=5)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response.headers["allow"], "POST")

    def logged(self, event: str) -> list[dict]:
        return [call.kwargs for call in module._log_event.call_args_list if call.args[1] == event]

    async def test_sessions_are_counted_once_per_handshake(self) -> None:
        # asyncSetUp's initialize is the only handshake so far.
        starts = self.logged("mcp.session.start")
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["method"], "initialize")
        self.assertEqual(starts[0]["client_name"], "regression-tests")
        self.assertEqual(starts[0]["client_version"], "1.0")
        self.assertEqual(starts[0]["protocol_version"], "2025-06-18")
        await self.rpc("tools/list", {})
        await self.call("get_recent_scans")
        self.assertEqual(len(self.logged("mcp.session.start")), 1)
        # The per-request lifespan no longer logs a "session" at INFO.
        self.assertEqual(self.logged("mcp.session.open"), [])
        # 2026-07-28 clients open with server/discover and carry clientInfo in _meta.
        await self.raw_post(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "Anthropic/ClaudeAI", "version": "1.0"},
                    }
                },
            },
            "application/json, text/event-stream",
        )
        discover = self.logged("mcp.session.start")[-1]
        self.assertEqual(
            (discover["method"], discover["client_name"], discover["protocol_version"]),
            ("server/discover", "Anthropic/ClaudeAI", "2026-07-28"),
        )


class ServerInternalsTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_auth_token_is_enforced(self) -> None:
        # Setting MCP_AUTH_TOKEN used to crash create_server: the mcp.auth log
        # line passed pydantic URL objects to json.dumps. _log_event is left
        # unpatched here so that line really runs.
        upstream = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
            base_url="https://scanmalware.com",
        )
        self.addAsyncCleanup(upstream.aclose)
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "auth", "version": "1"}},
        }
        accept = {"accept": "application/json, text/event-stream"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "_configure_logging"))
            stack.enter_context(patch.dict("os.environ", {"MCP_AUTH_TOKEN": "s3cret-token"}, clear=True))
            stack.enter_context(patch.object(module, "_MCP_HTTP_LOGGING_ENABLED", True))
            raw_log = stack.enter_context(patch.object(module, "_log_mcp_http_event"))
            stack.enter_context(
                patch.object(module, "_get_shared_client", new=AsyncMock(return_value=(upstream, "https://scanmalware.com")))
            )
            previous_log_level = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            self.addCleanup(logging.disable, previous_log_level)
            server = module.create_server(host="0.0.0.0", port=8000)
            app = server.streamable_http_app()
            async with server.session_manager.run():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000"
                ) as client:
                    missing = await client.post("/mcp", headers=accept, json=initialize)
                    wrong = await client.post(
                        "/mcp", headers={**accept, "authorization": "Bearer wrong"}, json=initialize
                    )
                    right = await client.post(
                        "/mcp", headers={**accept, "authorization": "Bearer s3cret-token"}, json=initialize
                    )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(right.status_code, 200, right.text)
        self.assertNotIn("s3cret-token", str(raw_log.call_args_list))
        self.assertIn("<redacted>", str(raw_log.call_args_list))

    async def test_production_host_header_is_accepted(self) -> None:
        # Production binds 0.0.0.0 behind nginx, which forwards
        # Host: mcp.scanmalware.com. The SDK switches on DNS-rebinding protection
        # (a localhost-only Host list) only for localhost binds.
        upstream = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
            base_url="https://scanmalware.com",
        )
        self.addAsyncCleanup(upstream.aclose)
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "_configure_logging"))
            stack.enter_context(patch.object(module, "_log_event"))
            stack.enter_context(patch.dict("os.environ", {}, clear=True))
            stack.enter_context(
                patch.object(module, "_get_shared_client", new=AsyncMock(return_value=(upstream, "https://scanmalware.com")))
            )
            server = module.create_server(host="0.0.0.0", port=8000)
            app = server.streamable_http_app()
            async with server.session_manager.run():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://mcp.scanmalware.com"
                ) as client:
                    response = await client.post(
                        "/mcp",
                        headers={"accept": "application/json, text/event-stream", "x-real-ip": "203.0.113.7"},
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "prod-shape", "version": "1"},
                            },
                        },
                    )
        self.assertEqual(response.status_code, 200, response.text)

    async def test_cancelled_tool_calls_are_logged(self) -> None:
        # A client that disconnects mid-call cancels the tool. CancelledError is a
        # BaseException, so it used to leave a start event and nothing else.
        started = asyncio.Event()

        async def slow_tool() -> dict:
            started.set()
            await asyncio.sleep(3600)
            return {}

        wrapped = module._wrap_with_logging(slow_tool, name="slow_tool", kind="tool")
        with patch.object(module, "_log_event") as log_event:
            task = asyncio.create_task(wrapped())
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        events = [call.args[1] for call in log_event.call_args_list]
        self.assertEqual(events, ["mcp.tool.start", "mcp.tool.cancelled"])
        self.assertEqual(log_event.call_args_list[-1].kwargs["tool"], "slow_tool")

    def test_every_api_path_value_is_validated_or_encoded(self) -> None:
        # Guards new tools against interpolating free text into an API path.
        # These names are UUID-checked, ipaddress-normalised, ints or Literals.
        safe_names = {"scan_id", "ip_address", "asn_number", "hash_type", "mmh3_hash", "fingerprint_id"}
        tree = ast.parse(Path(module.__file__).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            literal = "".join(part.value for part in node.values if isinstance(part, ast.Constant))
            if not literal.startswith("/api/v1/"):
                continue
            for part in node.values:
                if not isinstance(part, ast.FormattedValue):
                    continue
                value = part.value
                with self.subTest(line=node.lineno, value=ast.unparse(value)):
                    if isinstance(value, ast.Name):
                        self.assertIn(value.id, safe_names)
                    else:
                        self.assertIsInstance(value, ast.Call)
                        self.assertEqual(ast.unparse(value.func), "_path_segment")


if __name__ == "__main__":
    unittest.main()
