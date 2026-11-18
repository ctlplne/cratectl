#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cold_snapshot import MIGRATION_18, REQUIRED, SNAPSHOT, capture, check_restored_database, materialize, verify


class ColdSnapshotTests(unittest.TestCase):
    def setUp(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        temporary = tempfile.TemporaryDirectory(prefix='cratectl-cold-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'captured'
        for name in REQUIRED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {'journal-checkpoint.json': json.dumps([
                {'tenant': 'one', 'event_count': 1, 'last_sequence': 1, 'last_hash': '9' * 64}]).encode(),
                    'database/PG_VERSION': b'16\n', 'pagination.key': b'A' * 43 + b'\n'}.get(name, b'owned inert fixture')
            path.write_bytes(data)
        (self.root / 'database/empty').mkdir()
        payload = b'owned inert artifact'
        digest = hashlib.sha256(payload).hexdigest()
        self.object = Path('installation/objects/one/sha256') / digest[:2] / digest
        (self.root / self.object).parent.mkdir(parents=True)
        (self.root / self.object).write_bytes(payload)
        mock = patch('cold_snapshot.run_owned_client', return_value=(0, 'backup successfully verified'))
        self.postgres = mock.start()
        self.addCleanup(mock.stop)

    def create(self):
        return capture(self.root/'database', self.root/'installation', self.root/'pagination.key',
                       self.root/'journal-checkpoint.json', self.output)

    def test_seals_and_verifies_matching_metadata_and_bytes(self):
        digest = self.create()
        report = verify(self.output, digest)
        self.assertEqual(self.postgres.call_count, 2)
        self.assertEqual(report['verified_cas_files'], 1)
        self.assertIn('database/empty', report['directories'])
        self.assertIn(self.object.as_posix(), report['files'])
        self.assertEqual(hashlib.sha256((self.output/SNAPSHOT).read_bytes()).hexdigest(), digest)
        with self.assertRaisesRegex(ValueError, 'snapshot manifest SHA-256 differs'):
            verify(self.output, '0' * 64)
        self.assertEqual(self.postgres.call_count, 2)

    def test_materialization_never_publishes_changed_or_partial_inputs(self):
        digest = self.create()
        target = self.root / 'restored'
        self.assertEqual(materialize(self.output, digest, target), target)
        self.assertEqual(verify(target, digest), verify(self.output, digest))
        with self.assertRaisesRegex(ValueError, 'snapshot output already exists'):
            materialize(self.output, digest, target)
        with self.assertRaisesRegex(ValueError, 'restore output must be outside'):
            materialize(self.output, digest, self.output / 'child')
        (self.output / 'installation/server.key').write_bytes(b'changed')
        refused = self.root / 'refused'
        with self.assertRaisesRegex(ValueError, 'snapshot file or directory inventory differs'):
            materialize(self.output, digest, refused)
        self.assertFalse(refused.exists())
        self.assertEqual((target/SNAPSHOT).read_bytes(), (self.output/SNAPSHOT).read_bytes())

    def test_refuses_an_incomplete_or_mismatched_snapshot_before_postgres(self):
        digest = self.create()
        path = self.output / 'installation/server.key'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'missing required'):
            verify(self.output, digest)
        path.write_bytes(original)
        (self.output / self.object).write_bytes(b'changed bytes')
        with self.assertRaisesRegex(ValueError, 'content-addressed bytes differ'):
            verify(self.output, digest)
        self.assertEqual(self.postgres.call_count, 1)

    def test_preserves_unverified_source_and_refuses_unsafe_or_wrong_inputs(self):
        path = self.root/'installation/server.key'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'owned bounded private regular file'):
            self.create()
        path.chmod(0o600)
        self.postgres.return_value = (1, 'actual tool would refuse this fixture')
        with self.assertRaisesRegex(ValueError, 'stock pg_verifybackup failed'):
            self.create()
        self.assertFalse(self.output.exists())
        self.assertTrue(path.is_file())

    def test_restored_database_requires_exact_checkpoint_and_current_reference_sizes(self):
        digest = self.create()
        entry = self.output / self.object
        journal = json.loads((self.output/'journal-checkpoint.json').read_bytes())
        reference = {'tenant': 'one', 'digest': self.object.name, 'size': entry.stat().st_size}
        result = {'schema': {'version': 18, 'checksum': MIGRATION_18}, 'runtime_restricted': True,
                  'runtime_stopped': True, 'coverage': {'tenant_tables': 57, 'forced': 57, 'runtime_owned': 0},
                  'journal': journal, 'references': [reference]}

        def replay(value):
            self.postgres.side_effect = [(0, 'backup successfully verified'), (0, json.dumps(value))]
            return check_restored_database(self.output, digest)

        self.assertEqual(replay(result), {'schema': 18, 'forced_tenant_tables': 57,
                                          'journal_heads': 1, 'matched_object_references': 1})
        self.assertIn('READ ONLY', self.postgres.call_args.kwargs['input_text'])
        for altered, message in [({'journal': [{**journal[0], 'last_hash': '8' * 64}]}, 'journal heads differ'),
                                 ({'runtime_stopped': False}, 'stopped runtime differs'),
                                 ({'references': [{**reference, 'size': 0}]}, 'no verified bytes'),
                                 ({'references': [{**reference, 'tenant': 'other'}]}, 'no verified bytes')]:
            with self.subTest(change=list(altered)), self.assertRaisesRegex(ValueError, message):
                replay({**result, **altered})


if __name__ == '__main__':
    unittest.main()
