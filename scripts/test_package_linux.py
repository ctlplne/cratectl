#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from package_linux import archive_candidate, digest


class LinuxCandidateTests(unittest.TestCase):
    def test_archive_bytes_and_member_metadata_are_reproducible(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-archive-test-') as folder:
            root = Path(folder)
            binaries = root / 'input'
            binaries.mkdir()
            entries = {}
            for name in ('cratectl', 'cratectld'):
                file = binaries / name
                file.write_bytes(name.encode('ascii'))
                file.chmod(0o700)
                entries[name] = {'bytes': file.stat().st_size, 'sha256': digest(file)}
            manifest = {'binaries': entries, 'candidate': 'a' * 40, 'distribution_approved': False}
            one, two = root / 'a.tar.gz', root / 'b.tar.gz'
            archive_candidate(one, binaries, manifest)
            (binaries / 'cratectld').chmod(0o755)
            archive_candidate(two, binaries, manifest)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with tarfile.open(one, 'r:gz') as archive:
                self.assertEqual(archive.getnames(), ['manifest.json', 'cratectl', 'cratectld'])
                self.assertEqual(json.load(archive.extractfile('manifest.json')), manifest)
                for name in entries:
                    info = archive.getmember(name)
                    self.assertEqual((info.mode, info.uid, info.gid, info.mtime), (0o755, 0, 0, 0))
                    self.assertEqual(archive.extractfile(info).read(), name.encode('ascii'))
            original = one.read_bytes()
            archive_candidate(one, binaries, manifest)
            with self.assertRaisesRegex(ValueError, 'Existing candidate artifact differs'):
                archive_candidate(one, binaries, {**manifest, 'candidate': 'b' * 40})
            self.assertEqual(one.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
