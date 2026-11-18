#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import gzip
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from package_linux import BINARIES, SOURCE_INPUTS, archive_candidate, digest, write_checksums
from verify_linux_candidate import verify


class LinuxCandidateTests(unittest.TestCase):
    def test_checksum_bytes_are_canonical_and_preserve_existing_evidence(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-checksums-') as folder:
            root = Path(folder)
            entries = {'cratectl-linux-arm64.tar.gz': 'b' * 64, 'cratectl-linux-amd64.tar.gz': 'a' * 64}
            write_checksums(root, entries)
            expected = ('a' * 64 + '  cratectl-linux-amd64.tar.gz\n' + 'b' * 64 + '  cratectl-linux-arm64.tar.gz\n').encode()
            self.assertEqual((root / 'SHA256SUMS').read_bytes(), expected)
            write_checksums(root, entries)
            with self.assertRaisesRegex(ValueError, 'Existing candidate artifact differs'):
                write_checksums(root, {**entries, 'cratectl-linux-arm64.tar.gz': 'c' * 64})
            self.assertEqual((root / 'SHA256SUMS').read_bytes(), expected)

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

    def test_verifies_trusted_exact_archive_and_refuses_bad_members(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-archive-verify-') as folder:
            root = Path(folder)
            output = root / 'native.tar.gz'
            header = bytearray(64)
            header[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<H', header, 18, 183)
            for name in BINARIES:
                (root / name).write_bytes(header)
            manifest = {'schema': 1, 'profile': 'cratectl-linux-binary-candidate-v1', 'candidate': 'a' * 40,
                        'go_version': '1.27.4', 'platform': 'linux/arm64', 'distribution_approved': False,
                        'source_sha256': dict.fromkeys(SOURCE_INPUTS, 'b' * 64),
                        'binaries': {name: {'bytes': len(header), 'sha256': digest(root / name)} for name in BINARIES}}
            archive_candidate(output, root, manifest)
            self.assertEqual(verify(output, digest(output)), manifest)
            staged = root / 'staged'
            staged.mkdir()
            with self.assertRaisesRegex(ValueError, 'archive platform differs'):
                verify(output, digest(output), install_for='linux/amd64', staging=staged)
            self.assertEqual(list(staged.iterdir()), [])
            with self.assertRaisesRegex(ValueError, 'compressed archive SHA-256 differs'):
                verify(output, 'c' * 64, install_for='linux/arm64', staging=staged)
            self.assertEqual(list(staged.iterdir()), [])
            self.assertEqual(verify(output, digest(output), install_for='linux/arm64', staging=staged), manifest)
            self.assertEqual({p.name for p in staged.iterdir()}, {'manifest.json', *BINARIES})
            self.assertEqual(json.loads((staged / 'manifest.json').read_text()), manifest)
            for name in BINARIES:
                self.assertEqual((staged / name).read_bytes(), header)
                self.assertEqual((staged / name).stat().st_mode & 0o777, 0o755)
            with self.assertRaisesRegex(ValueError, 'compressed archive SHA-256 differs'):
                verify(output, 'c' * 64)
            bad = root / 'different-machine.tar.gz'
            struct.pack_into('<H', header, 18, 62)
            (root / 'cratectl').write_bytes(header)
            archive_candidate(bad, root, manifest)
            with self.assertRaisesRegex(ValueError, 'ELF class or architecture differs'):
                verify(bad, digest(bad))
            trailing = root / 'trailing.tar.gz'
            trailing.write_bytes(gzip.compress(gzip.decompress(output.read_bytes()) + b'unexpected', mtime=0))
            with self.assertRaisesRegex(ValueError, 'terminator or trailing members differ'):
                verify(trailing, hashlib.sha256(trailing.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
