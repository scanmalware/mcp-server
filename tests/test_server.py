from __future__ import annotations

import asyncio
import json
import logging
import unittest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

import httpx

from scanmalware_mcp import server as module


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

    async def call(self, name: str, **arguments: object) -> dict:
        return await self.rpc("tools/call", {"name": name, "arguments": arguments})

    async def test_slow_queries_get_more_time_without_changing_other_tools(self) -> None:
        for name, args, expected in (
            ("get_favicon_stats", {}, 90),
            ("search_ocr", {"q": "phishing"}, 90),
            # ~31 s per call, measured 2026-10-07; the 30 s default timed out every time.
            ("get_jsfingerprint_similarity_counts", {"fingerprint_id": 10448358}, 90),
            # 57 s for a cold query, 0.2 s once cached.
            ("search_js_fingerprinter2_signature", {"signature": "fetch:4|complex"}, 90),
            ("get_recent_scans", {}, 30),
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

    async def test_filterless_searches_are_rejected_before_upstream(self) -> None:
        for name in ("search_js_obfuscation", "search_js_malware_families", "search_js_fingerprint_patterns"):
            result = await self.call(name, limit=5)
            self.assertTrue(result.get("isError"), result)
        self.assertEqual(self.requests, [])

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
        self.route = lambda request: httpx.Response(200, content=png, headers={"content-type": "image/png"})
        result = await self.call("get_favicon", scan_id=self.SCAN_ID)
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(result["structuredContent"]["found"], True)
        self.assertEqual(result["structuredContent"]["size_bytes"], len(png))

    async def test_signature_is_sent_as_one_encoded_path_segment(self) -> None:
        result = await self.call("search_js_fingerprinter2_signature", signature="setTimeout:30|fetch:4/x?y#z")
        self.assertFalse(result.get("isError"), result)
        request = self.requests[-1]
        self.assertTrue(
            request.url.raw_path.startswith(
                b"/api/v1/js-fingerprinter2/search/signature/setTimeout%3A30%7Cfetch%3A4%2Fx%3Fy%23z?"
            ),
            request.url.raw_path,
        )
        self.assertEqual(dict(request.url.params), {"limit": "20"})
        result = await self.call("search_js_fingerprinter2_signature", signature="   ")
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
        # "Get OCR stats." failed that bar for most of the 128 tools.
        tools = await self.tools()
        self.assertEqual(len(tools), 128)
        for name, tool in tools.items():
            with self.subTest(tool=name):
                self.assertGreaterEqual(len(tool.get("description") or ""), 60)

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
        # titles as names that do not communicate their purpose. Titles are what
        # users see, so internal service names stay out of them.
        tools = await self.tools()
        for name, tool in tools.items():
            title = tool.get("title") or ""
            with self.subTest(tool=name, title=title):
                self.assertNotRegex(title, r"(?i)netlog|fingerprinter")


if __name__ == "__main__":
    unittest.main()
