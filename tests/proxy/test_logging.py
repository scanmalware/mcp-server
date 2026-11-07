from __future__ import annotations

import base64
import http.client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mitmproxy import http


ADDON = Path(__file__).resolve().parents[2] / 'deploy/mitmproxy/log_full.py'


class ProxyLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = Path(tmp.name) / 'full.log'
        with patch.dict(os.environ, {'MITMPROXY_FULL_LOG': str(self.log), 'MITMPROXY_LOG_MAX_BODY_BYTES': '16'}):
            spec = importlib.util.spec_from_file_location('proxy_log_test', ADDON)
            self.addon = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.addon)

    def test_body_capture_is_bounded_and_identifies_truncation(self) -> None:
        captured = self.addon._b64(b'x' * 128)
        self.assertEqual(base64.b64decode(captured['base64']), b'x' * 16)
        self.assertEqual((captured['length'], captured['captured'], captured['truncated']), (128, 16, True))

    def test_streamed_body_is_not_reconstructed_for_logging(self) -> None:
        response = http.Response.make(200, b'')
        response.raw_content = None
        self.assertIsNone(self.addon._message_body(response))

    def test_credentials_and_cookies_are_redacted(self) -> None:
        headers = http.Headers([(b'Authorization', b'fake-secret'), (b'Set-Cookie', b'private-cookie'),
                                (b'X-API-Key', b'fake-key'), (b'Content-Type', b'application/json')])
        result = dict(self.addon._headers(headers))
        self.assertEqual(result['Authorization'], '<redacted>')
        self.assertEqual(result['Set-Cookie'], '<redacted>')
        self.assertEqual(result['X-API-Key'], '<redacted>')
        self.assertEqual(result['Content-Type'], 'application/json')


@unittest.skipUnless(shutil.which('mitmdump'), 'requires the built proxy image')
class ProxyStreamingTests(unittest.TestCase):
    def test_headers_arrive_before_upstream_finishes_and_stream_is_not_retained(self) -> None:
        release = threading.Event()
        payload = b'x' * 256

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload[:64])
                self.wfile.flush()
                release.wait(5)
                self.wfile.write(payload[64:])

            def log_message(self, *args):
                pass

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log = Path(tmp.name) / 'full.log'
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        upstream.daemon_threads = True
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        errors = open(Path(tmp.name) / 'proxy.stderr', 'w+')
        self.addCleanup(errors.close)
        process = subprocess.Popen([
            'mitmdump', '--quiet', '--listen-host', '127.0.0.1', '--listen-port', str(port),
            '--set', 'confdir=' + str(Path(tmp.name) / 'state'),
            '--set', 'connection_strategy=lazy', '--set', 'http2=false', '--set', 'http3=false',
            '--set', 'stream_large_bodies=32', '--set', 'store_streamed_bodies=false',
            '--set', 'body_size_limit=256', '-s', str(ADDON),
        ], env={**os.environ, 'MITMPROXY_FULL_LOG': str(log), 'MITMPROXY_LOG_MAX_BODY_BYTES': '16'},
            stdout=errors, stderr=errors)

        def stop_proxy():
            release.set()
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

        self.addCleanup(stop_proxy)
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                errors.seek(0)
                self.fail('mitmdump exited: ' + errors.read())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1): break
            except OSError:
                if time.monotonic() > deadline: self.fail('proxy did not start')
                time.sleep(0.05)

        client = http_client.HTTPConnection('127.0.0.1', port, timeout=2)
        self.addCleanup(client.close)
        client.request('GET', f'http://127.0.0.1:{upstream.server_port}/fixture')
        # This times out under the old buffered configuration: the fixture waits
        # for us to receive the headers before it sends the rest of its 256 bytes.
        response = client.getresponse()
        self.assertEqual(response.status, 200)
        self.assertFalse(release.is_set())
        release.set()
        self.assertEqual(response.read(), payload)
        deadline = time.monotonic() + 2
        while True:
            events = [json.loads(line) for line in log.read_text().splitlines()]
            completed = [event for event in events if event['event'] == 'http.response']
            if completed: break
            if time.monotonic() > deadline: self.fail('response was not logged')
            time.sleep(0.02)
        self.assertTrue(completed[0]['response']['stream'])
        self.assertIsNone(completed[0]['response']['body'])


if __name__ == '__main__': unittest.main()
