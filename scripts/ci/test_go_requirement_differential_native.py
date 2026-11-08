# SPDX-License-Identifier: BUSL-1.1
"""Metadata response stand-ins only; no local Go SDK/registry/namespace claim."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from go_requirement_differential_native import check_downloads, check_listing, values


class DifferentialOracleTests(unittest.TestCase):
    def setUp(self):
        self.expected = [{'module': 'example.invalid/aa-original', 'version': 'v1.0.0',
                          'source_module': 'example.invalid/zz-fork', 'source_version': 'v1.2.0'},
                         {'module': 'example.invalid/mm-leaf', 'version': 'v1.0.0',
                          'source_module': 'example.invalid/mm-leaf', 'source_version': 'v1.0.0'}]
        self.listing = [{'Path': 'go.cratectl.invalid/owned-differential', 'Main': True},
                        {'Path': 'example.invalid/aa-original', 'Version': 'v1.0.0',
                         'Replace': {'Path': 'example.invalid/zz-fork', 'Version': 'v1.2.0'}},
                        {'Path': 'example.invalid/mm-leaf', 'Version': 'v1.0.0'}]

    def encode(self, objects):
        return b'\n'.join(json.dumps(v).encode() for v in objects)

    def test_logical_replacement_and_physical_identity_are_independent(self):
        check_listing(self.encode(list(reversed(self.listing))), self.expected)
        for kind in ['logical', 'logical-version', 'physical', 'physical-version', 'duplicate', 'missing', 'error', 'main']:
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.listing)
                if kind == 'logical':
                    changed[1]['Path'] = changed[1]['Replace']['Path']
                elif kind == 'logical-version':
                    changed[1]['Version'] = 'v1.2.0'
                elif kind == 'physical':
                    changed[1]['Replace']['Path'] = changed[1]['Path']
                elif kind == 'physical-version':
                    changed[1]['Replace']['Version'] = 'v1.0.0'
                elif kind == 'duplicate':
                    changed[2] = copy.deepcopy(changed[1])
                elif kind == 'missing':
                    changed.pop()
                elif kind == 'error':
                    changed[1]['Replace']['Error'] = {'Err': 'owned missing module'}
                else:
                    changed[0]['Path'] = 'example.invalid/unexpected-main'
                with self.assertRaises(ValueError):
                    check_listing(self.encode(changed), self.expected)

    def test_download_oracle_refuses_changed_sums_assets_and_duplicate_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'assets').mkdir()
            asset = directory / 'assets' / 'owned.txt'
            asset.write_bytes(b'owned inert differential asset')
            roots = [{'module': r['source_module'], 'version': r['source_version'],
                      'zip_h1': 'h1:owned-zip-' + str(n), 'mod_h1': 'h1:owned-mod-' + str(n)}
                     for n, r in enumerate(self.expected)]
            downloaded = [{'Path': r['module'], 'Version': r['version'], 'Sum': r['zip_h1'],
                           'GoModSum': r['mod_h1'], 'Dir': str(directory)} for r in roots]
            check_downloads(self.encode(list(reversed(downloaded))), roots)
            for kind in ['zip', 'mod', 'duplicate', 'missing', 'logical', 'asset', 'error']:
                with self.subTest(kind=kind):
                    changed = copy.deepcopy(downloaded)
                    asset.write_bytes(b'owned inert differential asset')
                    if kind == 'zip':
                        changed[0]['Sum'] += '-changed'
                    elif kind == 'mod':
                        changed[0]['GoModSum'] += '-changed'
                    elif kind == 'duplicate':
                        changed[1] = copy.deepcopy(changed[0])
                    elif kind == 'missing':
                        changed.pop()
                    elif kind == 'logical':
                        changed[0]['Path'] = self.expected[0]['module']
                    elif kind == 'asset':
                        asset.write_bytes(b'changed inert asset')
                    else:
                        changed[0]['Error'] = 'owned missing ZIP'
                    with self.assertRaises(ValueError):
                        check_downloads(self.encode(changed), roots)

    def test_sdk_stream_refuses_errors_ambiguity_and_resource_overflow(self):
        for raw in [b'', b'[]', b'{"Path":"a","Path":"b"}', b'{"Error":"owned refusal"}',
                    b'{}\n' * 17, b' ' * ((1 << 20) + 1)]:
            with self.subTest(size=len(raw)):
                with self.assertRaises((ValueError, TypeError)):
                    values(raw)


if __name__ == '__main__':
    unittest.main()
