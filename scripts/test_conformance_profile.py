#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Invalid profiles cannot become empty passing campaigns or touch a database."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('conformance.py')


class ConformanceProfile(unittest.TestCase):
    def test_actual_maven_version_gate_with_a_client_stand_in(self):
        # Load the real fixture's imports and function, without running its
        # database/bootstrap module body or any JVM command.
        source = ast.parse(SCRIPT.read_text())
        body = [node for node in source.body if isinstance(node, (ast.Import, ast.ImportFrom))
                or isinstance(node, ast.FunctionDef) and node.name == 'maven']
        namespace = {}
        exec(compile(ast.Module(body=body, type_ignores=[]), str(SCRIPT), 'exec'), namespace)

        class IdentityObserved(Exception):
            pass

        for observed, accepted in [('Apache Maven 3.10.0 (native build)\n', True),
                                   ('\x1b[1mApache Maven 3.10.0\x1b[0m\n', True),
                                   ('Apache Maven 3.9.9 (unexpected build)\n', False),
                                   ('Apache Maven development\n', False)]:
            with self.subTest(observed=observed), tempfile.TemporaryDirectory(prefix='cratectl-maven-identity-') as directory:
                root = Path(directory)
                (root / '.cache').mkdir()
                archive = root / '.cache/apache-maven-3.10.0-bin.tar.gz'
                archive.write_bytes(b'owned distribution stand-in; never executed')
                pin = {'maven': {'version': '3.10.0', 'sha512': hashlib.sha512(archive.read_bytes()).hexdigest()}}
                pins = root / 'docs/qualification/jvm-clients.json'
                pins.parent.mkdir(parents=True)
                pins.write_text(json.dumps(pin))
                calls = []

                def run(arguments, *_):
                    calls.append(arguments)
                    if arguments[-1] == '--version':
                        return observed
                    raise AssertionError('stand-in must stop before package commands')

                def check(name, condition):
                    self.assertTrue(condition, name)

                def repository(*_):
                    pass

                class Stages(list):
                    def append(self, stage):
                        super().append(stage)
                        raise IdentityObserved()

                # Stop at the first completed stage, before deployment starts.
                class Result(dict):
                    def __setitem__(self, key, value):
                        if key == 'maven_cache_contract':
                            value['completed'] = Stages()
                        super().__setitem__(key, value)

                result = Result()
                namespace.update(ROOT=root, PRIVATE=root, result=result, repository=repository,
                                 tokens={'admin': 'owned-inert-stand-in'}, run=run, check=check, commands=[])
                with self.assertRaises(IdentityObserved if accepted else AssertionError):
                    namespace['maven']()
                self.assertEqual(len(calls), 1)
                self.assertEqual(result['maven_cache_contract']['completed'], ['client_identity'] if accepted else [])

    def test_unknown_profile_and_flags_fail_before_reading_database_configuration(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-profile-') as directory:
            env = dict(os.environ, CRATECTL_CONFORMANCE_DATABASE_FILE=str(Path(directory) / 'must-not-exist'))
            for arguments in [['unimplemented-profile'], ['gradle', '--require-cleen-build']]:
                result = subprocess.run([sys.executable, SCRIPT, *arguments], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('usage:', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertNotIn('must-not-exist', result.stderr)

    def test_help_needs_no_database_or_client_runtime(self):
        result = subprocess.run([sys.executable, SCRIPT, '--help'], env=dict(os.environ, CRATECTL_CONFORMANCE_DATABASE_FILE='/nonexistent/cratectl-profile'), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn('gradle', result.stdout)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
