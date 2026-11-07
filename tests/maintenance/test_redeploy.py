from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "deploy/redeploy.sh"
DOCKER_STUB = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['FAKE_DOCKER_LOG'], 'a') as f: f.write(json.dumps(args) + '\\n')
if args[:2] == ['image', 'inspect']: print('sha256:oldimage')
if args and args[0] == 'compose':
    config = pathlib.Path(args[args.index('-f') + 1])
    if 'config' in args:
        print('scanmalware-mcp:test' if '--images' in args else 'services: {}')
    if 'build' in args and os.environ.get('FAIL_BUILD'): sys.exit(7)
    if 'up' in args and os.environ.get('FAIL_START') and config.name == 'docker-compose.yml' and config.parent.parent.joinpath('version').read_text() == 'new': sys.exit(9)
'''


class RedeployTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "release with spaces"
        self.new = self.base / "archive"
        for root, version in ((self.root, "old"), (self.new, "new")):
            (root / "deploy/mitmproxy/state").mkdir(parents=True)
            (root / "deploy/docker-compose.yml").write_text("services: {}\n")
            (root / "version").write_text(version)
            (root / "version").chmod(0o644)
        (self.root / ".env").write_text("SCANMALWARE_TIMEOUT_S=45\n")
        (self.root / "deploy/.env").write_text("SCANMALWARE_MAX_JSON_BYTES=5000\n")
        (self.root / "deploy/mitmproxy/state/mitmproxy-ca-cert.pem").write_text("test certificate")
        (self.root / "logs").mkdir()
        (self.root / "logs/history.log").write_text("original history")
        self.archive = self.base / "release.tar.gz"
        with tarfile.open(self.archive, "w:gz") as tf:
            for child in self.new.iterdir(): tf.add(child, arcname=child.name)
        bindir = self.base / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(DOCKER_STUB)
        docker.chmod(0o755)
        self.log = self.base / "docker.jsonl"
        self.env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ['PATH'],
                    "ROOT_DIR": str(self.root), "FAKE_DOCKER_LOG": str(self.log)}
        for name in ("DEPLOY_ENV_FILE", "FAIL_BUILD", "FAIL_START"):
            self.env.pop(name, None)

    def deploy(self, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(self.archive)], env={**self.env, **env},
                              capture_output=True, text=True, timeout=10)

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def assert_preserved(self, version: str) -> None:
        self.assertEqual((self.root / "version").read_text(), version)
        self.assertEqual((self.root / ".env").read_text(), "SCANMALWARE_TIMEOUT_S=45\n")
        self.assertEqual((self.root / "deploy/.env").read_text(), "SCANMALWARE_MAX_JSON_BYTES=5000\n")
        self.assertEqual((self.root / "deploy/mitmproxy/state/mitmproxy-ca-cert.pem").read_text(), "test certificate")
        self.assertEqual((self.root / "logs/history.log").read_text(), "original history")
        self.assertFalse(Path(str(self.root) + ".deploy-lock").exists())

    def test_success_preserves_config_ca_and_logs_and_builds_before_stopping(self) -> None:
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_preserved("new")
        self.assertEqual((self.root / 'version').stat().st_mode & 0o777, 0o644)
        calls = self.calls()
        self.assertLess(next(i for i, x in enumerate(calls) if 'build' in x),
                        next(i for i, x in enumerate(calls) if 'down' in x))
        up = next(x for x in calls if 'up' in x)
        self.assertIn('--no-build', up)
        self.assertIn('--wait', up)
        self.assertEqual(list(self.base.glob('*.rollback.*')), [])

    def test_build_failure_leaves_running_release_and_config_intact(self) -> None:
        result = self.deploy(FAIL_BUILD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved("old")
        self.assertFalse(any('down' in x for x in self.calls()))
        self.assertTrue(any(x[:2] == ['image', 'tag'] and x[-1] == 'scanmalware-mcp:test' for x in self.calls()))

    def test_failed_start_restores_previous_release_and_image(self) -> None:
        result = self.deploy(FAIL_START='1')
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved("old")
        self.assertEqual(sum('up' in x for x in self.calls()), 2)
        self.assertNotIn('Automatic recovery needs attention', result.stderr)
        self.assertTrue(any(x[:2] == ['image', 'tag'] and x[-1] == 'scanmalware-mcp:test' for x in self.calls()))

    def test_external_env_file_is_explicit_for_every_compose_invocation(self) -> None:
        config = self.base / 'persistent.env'
        config.write_text('SCANMALWARE_TIMEOUT_S=60\n')
        result = self.deploy(DEPLOY_ENV_FILE=str(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text(), 'SCANMALWARE_TIMEOUT_S=60\n')
        for args in self.calls():
            if args[0] == 'compose': self.assertEqual(Path(args[args.index('--env-file') + 1]).resolve(), config.resolve())

    def test_bad_archive_is_rejected_before_stopping(self) -> None:
        with tarfile.open(self.archive, 'w:gz'): pass
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assert_preserved('old')
        self.assertFalse(self.log.exists())

    def test_public_deploy_without_dotenv_does_not_enable_auth(self) -> None:
        (self.root / '.env').unlink()
        (self.root / 'deploy/.env').unlink()
        result = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'version').read_text(), 'new')
        self.assertFalse((self.root / '.env').exists())
        self.assertFalse((self.root / 'deploy/.env').exists())
        for args in self.calls():
            if args[0] == 'compose': self.assertEqual(args[args.index('--env-file') + 1], '/dev/null')

    def test_overlapping_deploy_is_rejected_without_changing_existing_lock(self) -> None:
        lock = Path(str(self.root) + '.deploy-lock')
        lock.mkdir()
        result = self.deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(lock.is_dir())
        self.assertFalse(self.log.exists())
        self.assertEqual((self.root / 'version').read_text(), 'old')


if __name__ == '__main__': unittest.main()
