#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Reject metadata substitutions when binding a native Gradle publication."""
import copy
import hashlib
import unittest

from conformance_gradle import GROUP_PATH, publication_references


class GradlePublication(unittest.TestCase):
    def setUp(self):
        self.contents = {'jar': b'owned resource archive', 'pom': b'owned POM', 'module': b'owned module metadata'}

    def rows(self, version, suffix):
        stem = GROUP_PATH + '/gradle-app/' + version + '/gradle-app-' + suffix
        return [{'path': stem + '.' + ext, 'digest': hashlib.sha256(value).hexdigest(), 'size': len(value)} for ext, value in self.contents.items()]

    def bind(self, version, rows):
        return publication_references('gradle-app', version, self.contents, rows)

    def test_release_requires_each_exact_coordinate_digest_and_size(self):
        rows = self.rows('1.0.0', '1.0.0')
        self.assertEqual(set(self.bind('1.0.0', rows)), {'jar', 'pom', 'module'})
        for ext in ['jar', 'pom', 'module']:
            for field, bad in [('path', 'elsewhere/' + ext), ('digest', '0' * 64), ('size', 0)]:
                altered = copy.deepcopy(rows)
                next(row for row in altered if row['path'].endswith('.' + ext))[field] = bad
                with self.subTest(ext=ext, field=field), self.assertRaises(AssertionError):
                    self.bind('1.0.0', altered)
        with self.assertRaises(AssertionError):
            self.bind('1.0.0', rows + [rows[0]])

    def test_snapshot_binds_metadata_to_the_same_unique_timestamp_as_jar(self):
        old = self.rows('4.0-SNAPSHOT', '4.0-20261103.130000-1')
        # The prior POM and module are byte-identical; neither can fill a gap.
        old[0]['digest'] = '0' * 64
        current = self.rows('4.0-SNAPSHOT', '4.0-20261103.130001-2')
        result = self.bind('4.0-SNAPSHOT', old + current)
        self.assertTrue(all('20261103.130001-2' in row['path'] for row in result.values()))
        for ext in ['pom', 'module']:
            incomplete = [row for row in current if not row['path'].endswith('.' + ext)]
            with self.subTest(ext=ext), self.assertRaises(AssertionError):
                self.bind('4.0-SNAPSHOT', old + incomplete)

    def test_snapshot_alias_wrong_coordinate_and_ambiguous_build_are_rejected(self):
        current = self.rows('4.0-SNAPSHOT', '4.0-20261103.130001-2')
        for rows in [self.rows('4.0-SNAPSHOT', '4.0-SNAPSHOT'),
                     self.rows('3.0-SNAPSHOT', '3.0-20261103.130001-2'),
                     current + self.rows('4.0-SNAPSHOT', '4.0-20261103.130002-3'),
                     current * 34]:
            with self.subTest(rows=len(rows)), self.assertRaises(AssertionError):
                self.bind('4.0-SNAPSHOT', rows)


if __name__ == '__main__':
    unittest.main()
