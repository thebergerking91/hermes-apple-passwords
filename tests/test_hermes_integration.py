"""End-to-end checks through Hermes's real loader, CLI dispatch, secret orchestrator and vault.

Run with a current Hermes checkout (and its import dependencies) on PYTHONPATH. No macOS
credentials, real bridge, pairing, or live vault are used: a synthetic ``apwlib`` package
stands in for the dependency where a worker process must import it.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


PLUGIN = Path(__file__).resolve().parents[1]
REF = 'applepw://example.com/alice%40example.com/password'

FAKE_APWLIB = textwrap.dedent('''
    """Synthetic stand-in for apwlib: never touches a vault."""
    from types import SimpleNamespace

    class SessionError(Exception):
        pass

    class NotPairedError(SessionError):
        pass

    class Daemon:
        def __init__(self, socket_path=None, auto_start=True):
            pass

        def status(self):
            return {"running": True, "bridge": True, "paired": True, "browser": None, "browser_pid": None}

    class ApplePasswords:
        def __init__(self, socket_path=None, auto_start=True, pin_provider=None):
            assert auto_start is False and pin_provider is None

        def get_password(self, url, username=None):
            rows = [SimpleNamespace(username="alice@example.com", domain="example.com",
                                    password="synthetic-credential", title=None,
                                    sites=["example.com"], high_level_domain="example.com")]
            return [row for row in rows if not username or row.username == username]

        def get_otp(self, url):
            return []

        def list_otp(self, url):
            return []
''')


def _write_fake_apwlib(root: Path) -> Path:
    package = root / 'apwlib'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text(FAKE_APWLIB, encoding='utf-8')
    return root


def _install(home: Path) -> Path:
    env = dict(os.environ, HERMES_HOME=str(home))
    result = subprocess.run([sys.executable, str(PLUGIN / 'install.py'), '--home', str(home)],
                            env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return home / 'plugins' / 'apple-passwords'


def _write_config(home: Path, text: str) -> None:
    (home / 'config.yaml').write_text(textwrap.dedent(text), encoding='utf-8')


class HermesIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name) / 'profile'
        self.installed = _install(self.home)
        _write_config(self.home, '''
            plugins:
              enabled:
                - apple-passwords
            vault:
              apple_passwords:
                enabled: true
                domains:
                  - example.com
        ''')

    def _load(self):
        from hermes_cli.plugins import PluginManager
        from hermes_cli.plugins_manifest import parse_manifest_file

        manifest = parse_manifest_file(self.installed / 'plugin.yaml', self.installed, 'user', '')
        self.assertIsNotNone(manifest)
        manager = PluginManager(scope_key=str(self.home))
        manager._load_plugin(manifest)
        loaded = manager._plugins['apple-passwords']
        self.assertTrue(loaded.enabled, loaded.error)
        return manager

    def _plugin_module(self, leaf: str, source_obj):
        package = type(source_obj).__module__.rsplit('.', 1)[0]
        return importlib.import_module(f'{package}.{leaf}')

    def test_loader_registers_skill_cli_source_and_vault_backend(self):
        from agent.secret_sources.registry import get_source

        with patch.dict(os.environ, {'HERMES_HOME': str(self.home)}):
            manager = self._load()
            self.assertIn('apple-passwords:apple-passwords', manager._plugin_skills)
            command = manager._cli_commands['apple-passwords']
            top = argparse.ArgumentParser()
            subcommands = top.add_subparsers(dest='command')
            command['setup_fn'](subcommands.add_parser('apple-passwords'))
            parsed = top.parse_args(['apple-passwords', 'run', '--', '/usr/bin/true'])
            self.assertEqual(parsed.command, 'apple-passwords')
            source = get_source('apple_passwords', scope=str(self.home))
            self.assertIsNotNone(source)
            vault = self._plugin_module('vault', source)
            self.addCleanup(vault.uninstall)

            from agent.vault_backends import enabled_backends
            from agent.vault_backends import base as vault_base
            names = [backend.name for backend in enabled_backends()]
            self.assertIn('apple_passwords', names)
            self.assertIn('apple_passwords', [backend.name for backend in vault_base.enabled_backends()])

    def test_orchestrator_applies_values_with_onepassword_precedence(self):
        from agent.secret_sources.registry import apply_all, get_source

        with patch.dict(os.environ, {'HERMES_HOME': str(self.home)}):
            self._load()
            source = get_source('apple_passwords', scope=str(self.home))
            self.addCleanup(self._plugin_module('vault', source).uninstall)
            source_module = importlib.import_module(type(source).__module__)
            bridge = self._plugin_module('bridge', source)
            result = {'values': {REF: 'synthetic-credential'}, 'errors': {}}
            config = {'apple_passwords': {'enabled': True, 'cache_ttl_seconds': 0,
                                          'env': {'EXAMPLE_API_KEY': REF}}}
            with patch.object(bridge, 'dependency_available', return_value=True), \
                 patch.object(bridge, 'run_worker', return_value=result) as worker:
                environment = {'EXAMPLE_API_KEY': 'existing'}
                apply_all(config, self.home, environ=environment)
                # 1Password parity: the secret manager wins by default.
                self.assertEqual(environment['EXAMPLE_API_KEY'], 'synthetic-credential')
                config['apple_passwords']['override_existing'] = False
                environment = {'EXAMPLE_API_KEY': 'existing'}
                apply_all(config, self.home, environ=environment)
                self.assertEqual(environment['EXAMPLE_API_KEY'], 'existing')
            self.assertTrue(worker.called)
            source_module.clear_cache()

    def test_real_worker_imports_dependency_through_stripped_secret_env(self):
        """Regression: run_secret_cli drops PYTHONPATH; the worker must still import apwlib."""
        from agent.secret_sources.registry import get_source

        deps = _write_fake_apwlib(Path(self._tmp.name) / 'deps')
        environ = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        environ['HERMES_HOME'] = str(self.home)
        with patch.dict(os.environ, environ, clear=True), patch.object(sys, 'path', [str(deps), *sys.path]):
            importlib.invalidate_caches()
            sys.modules.pop('apwlib', None)
            self.addCleanup(sys.modules.pop, 'apwlib', None)
            self._load()
            source = get_source('apple_passwords', scope=str(self.home))
            self.addCleanup(self._plugin_module('vault', source).uninstall)
            source_module = importlib.import_module(type(source).__module__)
            if sys.platform != 'darwin':
                self.skipTest('worker credential lookups require macOS')
            status = source_module.bridge_status()
            self.assertEqual(status, {'dependency': True, 'running': True, 'bridge': True, 'paired': True})
            values, errors = source_module.resolve_references([REF])
            self.assertEqual((values, errors), ({REF: 'synthetic-credential'}, {}))
            rows = source_module.list_accounts('example.com')
            self.assertEqual([(row['host'], row['username']) for row in rows],
                             [('example.com', 'alice@example.com')])
            self.assertNotIn('synthetic-credential', json.dumps(rows))

    def test_browser_vault_lists_and_resolves_without_exposing_password(self):
        from agent.secret_sources.registry import get_source

        with patch.dict(os.environ, {'HERMES_HOME': str(self.home)}):
            self._load()
            source = get_source('apple_passwords', scope=str(self.home))
            vault = self._plugin_module('vault', source)
            self.addCleanup(vault.uninstall)
            bridge = self._plugin_module('bridge', source)
            rows = [{'host': 'example.com', 'hosts': ['example.com', 'www.example.com'],
                     'username': 'alice@example.com', 'has_otp': False},
                    {'host': 'evil.test', 'hosts': ['evil.test'], 'username': 'mallory', 'has_otp': False}]

            def worker(op, values=(), **_kwargs):
                if op == 'vault-list':
                    return rows
                if op == 'resolve':
                    return {'values': {ref: 'synthetic-credential' for ref in values}, 'errors': {}}
                raise AssertionError(op)

            with patch.object(bridge, 'dependency_available', return_value=True), \
                 patch.object(bridge, 'run_worker', side_effect=worker):
                from tools.browser_vault_tool import browser_vault_list
                from agent.vault_backends import backend_for_handle

                listing = json.loads(browser_vault_list())
                apple = [item for item in listing['items'] if item['backend'] == 'apple_passwords']
                self.assertEqual(len(apple), 1, listing)
                self.assertEqual(apple[0]['identifier'], 'alice@example.com')
                self.assertEqual(apple[0]['allowed_origins'], ['https://example.com', 'https://www.example.com'])
                self.assertNotIn('synthetic-credential', json.dumps(listing))
                backend = backend_for_handle(apple[0]['handle'])
                self.assertEqual(backend.name, 'apple_passwords')
                self.assertEqual(backend.resolve_password(apple[0]['handle']), 'synthetic-credential')

    def test_real_hermes_cli_dispatch_status_and_run_exit_codes(self):
        """Regression: `run` must not clobber Hermes's args.command and must return the child's code."""
        env = {key: value for key, value in os.environ.items()}
        env['HERMES_HOME'] = str(self.home)
        entry = ('import sys; from hermes_cli.main import main; '
                 'sys.argv = ["hermes", *sys.argv[1:]]; main()')

        def hermes(*argv):
            return subprocess.run([sys.executable, '-c', entry, *argv], env=env, capture_output=True,
                                  text=True, timeout=180, check=False)

        status = hermes('apple-passwords', 'status')
        self.assertEqual(status.returncode, 0, status.stderr[-2000:])
        self.assertIn('apwlib:', status.stdout)
        self.assertEqual(hermes('apple-passwords', 'run', '--', '/usr/bin/true').returncode, 0)
        failed = hermes('apple-passwords', 'run', '--', '/usr/bin/false')
        self.assertEqual(failed.returncode, 1, failed.stderr[-2000:])
        self.assertNotIn('Traceback', failed.stderr)


if __name__ == '__main__':
    unittest.main()
