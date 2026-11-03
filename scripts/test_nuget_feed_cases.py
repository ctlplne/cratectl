# SPDX-License-Identifier: BUSL-1.1
"""Keep the actual SDK HTTP corpus deterministic, complete and inert."""
import base64
import hashlib
import io
import json
import unittest
import xml.etree.ElementTree as XML
import zipfile

from nuget_feed_cases import archive, cases, difference_paths


class OwnedNuGetHTTPFixtures(unittest.TestCase):
    def test_extended_corpus_preserves_all_original_cases_and_fixture_identity(self):
        original=cases();extended=cases(extended=True)
        self.assertEqual(len(extended),56)
        self.assertEqual(extended[:44],original)
        for case in original:case['archive_sha256']=hashlib.sha256(archive(case)).hexdigest()
        self.assertEqual(hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'911a48eef175c1075cebc742c47b9a615459a157e71d326d062b4a80780c9bca')
        self.assertEqual([c['index'] for c in extended],list(range(56)))

    def test_diagnostics_identify_nested_differences_without_values(self):
        left = {'groups': [{'framework':'net10.0','packages':[{'id':'Owned.A','min':'private-synthetic-original'}]}], 'license_acceptance':True}
        right = {'groups': [{'framework':'unsupported','packages':[{'id':'Owned.A','min':'private-synthetic-http'},{'id':'Owned.B'}]}], 'license_acceptance':False}
        paths = difference_paths(left, right)
        self.assertEqual(paths, ['groups[0].framework','groups[0].packages._length','groups[0].packages[0].min','license_acceptance'])
        self.assertNotIn('private-synthetic', json.dumps(paths))

    def test_original_documents_and_archives_are_complete_bounded_and_inert(self):
        corpus = cases()
        self.assertEqual(len(corpus), 44)
        self.assertEqual(corpus, cases())
        self.assertEqual([c['index'] for c in corpus], list(range(44)))
        self.assertEqual(len({c['id'] for c in corpus}), 44)
        self.assertEqual([c['label'] for c in corpus if c['omit_float_comparison']], ['all-stable'])
        self.assertLess(len(json.dumps(corpus).encode()), 2 << 20)
        for case in corpus:
            with self.subTest(case=case['label']):
                raw = base64.b64decode(case['nuspec'], validate=True)
                XML.fromstring(raw)
                package = archive(case)
                self.assertEqual(package, archive(case))
                with zipfile.ZipFile(io.BytesIO(package)) as z:
                    self.assertEqual(z.namelist(), [case['id'] + '.nuspec', 'content/owned.txt'])
                    self.assertEqual(z.read(z.namelist()[0]), raw)
                    self.assertEqual(z.read('content/owned.txt'), b'Owned inert metadata fixture; never executed.\n')
                    self.assertIsNone(z.testzip())
                    self.assertTrue(all(info.date_time == (2026, 1, 1, 0, 0, 0) and info.external_attr >> 16 == 0o100644 for info in z.infolist()))


if __name__ == '__main__':
    unittest.main()
