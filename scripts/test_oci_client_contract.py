#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise native filesystem boundaries with real files, links and FIFOs."""
import os
from pathlib import Path
import tempfile
import unittest

from oci_client_contract import read_owned_file


class NativeClientFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cratectl-oci-client-', dir=Path(__file__).resolve().parents[1] / '.cache')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'private'
        self.root.mkdir(mode=0o700)
        self.outside = self.base / 'outside'
        self.outside.write_bytes(b'outside observation must not be read')

    def test_exact_binary_and_byte_budgets(self):
        path = self.root / 'copy'
        body = bytes(range(256)) * 4096
        path.write_bytes(body)
        self.assertEqual(read_owned_file(self.root, path, len(body)), body)
        for limit in [len(body) - 1, 0, -1, True, 33 << 20]:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                read_owned_file(self.root, path, limit)

    def test_symlink_components_and_hardlinks_are_rejected(self):
        (self.root / 'link').symlink_to(self.outside)
        (self.root / 'parent').symlink_to(self.base, target_is_directory=True)
        os.link(self.outside, self.root / 'hardlink')
        for path in [self.root / 'link', self.root / 'parent' / 'outside', self.root / 'hardlink', self.root / '..' / 'outside', self.outside]:
            with self.subTest(name=path.name), self.assertRaises(ValueError):
                read_owned_file(self.root, path, 4096)
        alias = self.base / 'root-link'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            read_owned_file(alias, alias / 'copy', 4096)

    def test_special_file_does_not_block_or_become_content(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            read_owned_file(self.root, fifo, 4096)
        with self.assertRaises(ValueError):
            read_owned_file(self.root, self.root, 4096)


if __name__ == '__main__':
    unittest.main()
