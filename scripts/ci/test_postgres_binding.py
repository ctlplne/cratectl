#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import subprocess
import sys
import unittest
from pathlib import Path

from check_postgres_binding import valid_binding


class PostgresBinding(unittest.TestCase):
    def test_exact_loopback(self):
        self.assertTrue(valid_binding({'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '35432'}]}))

    def test_rejects_broader_or_different_endpoints(self):
        for value in [None, [], {}, {'5432/tcp': None},
                      {'5432/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '35432'}]},
                      {'5432/tcp': [{'HostIp': '::', 'HostPort': '35432'}]},
                      {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5432'}]},
                      {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '35432'}, {'HostIp': '::', 'HostPort': '35432'}]},
                      {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '35432'}], '80/tcp': None}]:
            with self.subTest(value=value):
                self.assertFalse(valid_binding(value))

    def test_entrypoint_rejects_malformed_or_oversized_input(self):
        for raw in [b'{', b'\xff', b' ' * 16385]:
            completed = subprocess.run([sys.executable, Path(__file__).with_name('check_postgres_binding.py')], input=raw, capture_output=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b'CI PostgreSQL must expose exactly', completed.stderr)
            self.assertEqual(completed.stdout, b'')


if __name__ == '__main__':
    unittest.main()
