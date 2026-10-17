"""Load the installed plugin through Hermes's actual loader and secret orchestrator.

Run with a current Hermes checkout on PYTHONPATH and its test dependencies installed.
No macOS credentials or real bridge are used.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


PLUGIN = Path(__file__).resolve().parents[1]


class HermesIntegrationTests(unittest.TestCase):
    def test_install_load_register_and_apply_secret_with_precedence(self):
        from hermes_cli.plugins import PluginManager
        from hermes_cli.plugins_manifest import parse_manifest_file
        from agent.secret_sources.registry import apply_all, get_source

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'profile'
            env = dict(os.environ, HERMES_HOME=str(home))
            result = subprocess.run([sys.executable, str(PLUGIN / 'install.py'), '--home', str(home)],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = home / 'plugins' / 'apple-passwords'
            with patch.dict(os.environ, {'HERMES_HOME': str(home)}):
                manifest = parse_manifest_file(installed / 'plugin.yaml', installed, 'user', '')
                self.assertIsNotNone(manifest)
                manager = PluginManager(scope_key=str(home))
                manager._load_plugin(manifest)
                loaded = manager._plugins['apple-passwords']
                self.assertTrue(loaded.enabled, loaded.error)
                self.assertIn('apple-passwords:apple-passwords', manager._plugin_skills)
                command = manager._cli_commands['apple-passwords']
                parser = argparse.ArgumentParser()
                command['setup_fn'](parser)
                self.assertEqual(parser.parse_args(['status']).applepw_command, 'status')
                source = get_source('apple_passwords', scope=str(home))
                self.assertIsNotNone(source)
                module = importlib.import_module(type(source).__module__)
                response = subprocess.CompletedProcess([], 0,
                    json.dumps({'ok': True, 'result': 'synthetic-credential'}), '')
                config = {'apple_passwords': {'enabled': True, 'env': {
                    'EXAMPLE_API_KEY': 'applepw://example.com/alice/password'}}}
                with patch.object(module, 'run_secret_cli', return_value=response):
                    environment = {'EXAMPLE_API_KEY': 'existing'}
                    apply_all(config, home, environ=environment)
                    self.assertEqual(environment['EXAMPLE_API_KEY'], 'existing')
                    config['apple_passwords']['override_existing'] = True
                    apply_all(config, home, environ=environment)
                    self.assertEqual(environment['EXAMPLE_API_KEY'], 'synthetic-credential')


if __name__ == '__main__':
    unittest.main()
