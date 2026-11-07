#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pure field/guard/FS stand-ins; never alter a real kernel setting locally."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from prepare_owned_ports import MAX_FIELD, OWNED, guard, namespace_case, ports, read_field, render, reserve


class OwnedPorts(unittest.TestCase):
    def test_merge_preserves_unrelated_ranges_and_all_existing_ports(self):
        for original in ['', '1,2-4,10-10', '35432,38443', '0-65535', '40000-40002,35431-35433', '4,1-3,2-4']:
            with self.subTest(original=original):
                state = [original]
                writes = []
                def write(value):
                    writes.append(value)
                    state[0] = value
                result = reserve(lambda: state[0], write)
                self.assertEqual(ports(state[0]), ports(original) | OWNED)
                self.assertEqual(result['inherited_count'], len(ports(original)))
                self.assertEqual(result['owned_ports'], sorted(OWNED))
                self.assertEqual(len(writes), 1)
                replay = reserve(lambda: state[0], write)
                self.assertEqual(result['after_sha256'], replay['after_sha256'])

    def test_bad_or_excessive_inherited_field_never_writes(self):
        for raw in ['-1', '65536', '2-1', '1,', '1,,2', '1;2', '1\n2', '1-65536', 'x', '1' * (MAX_FIELD + 1)]:
            writes = []
            with self.subTest(length=len(raw)):
                with self.assertRaises(ValueError):
                    reserve(lambda: raw, writes.append)
                self.assertEqual(writes, [])

    def test_lost_write_truncation_and_unexpected_readback_never_pass(self):
        for after in ['', '35432', '35432,38443,40000']:
            inputs = iter(['1-3', after])
            with self.subTest(after=after):
                with self.assertRaisesRegex(ValueError, 'readback'):
                    reserve(lambda: next(inputs), lambda _: None)

    def test_render_canonical_and_boundaries(self):
        self.assertEqual(render(ports('4,1-3,2,65535,0')), '0-4,65535')
        for bad in [{-1}, {65536}, {True}]:
            with self.assertRaises(ValueError):
                render(bad)

    def test_only_root_disposable_native_github_linux_passes_guard(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                       'RUNNER_OS': 'Linux', 'CRATECTL_CI_POSTGRES_CONTAINER_ID': 'a' * 64}
        guard(environment, 'Linux', 0)
        for change in [{'GITHUB_ACTIONS': 'false'}, {'RUNNER_ENVIRONMENT': 'self-hosted'},
                       {'RUNNER_OS': 'macOS'}, {'CRATECTL_CI_POSTGRES_CONTAINER_ID': 'arbitrary'}]:
            with self.assertRaises(ValueError):
                guard({**environment, **change}, 'Linux', 0)
        for system, uid in [('Darwin', 0), ('Linux', 1000)]:
            with self.assertRaises(ValueError):
                guard(environment, system, uid)

    def test_field_read_is_bounded_before_any_write(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-port-field-') as directory:
            target = Path(directory) / 'owned-field'
            target.write_text('100-102\n')
            result = reserve(lambda: read_field(target), target.write_text)
            self.assertEqual(result['inherited_count'], 3)
            self.assertEqual(ports(target.read_text()), {100, 101, 102} | OWNED)
            target.write_text(' ' * (MAX_FIELD + 1))
            with self.assertRaises(ValueError):
                read_field(target)

    def test_namespace_pressure_refuses_parent_or_init_namespace_before_commands(self):
        for observed in [[11], [12, 12]]:
            with self.subTest(observed=observed), patch('prepare_owned_ports.os.stat', side_effect=[SimpleNamespace(st_ino=n) for n in observed]), patch('prepare_owned_ports.subprocess.run') as command, patch('pathlib.Path.write_text') as write:
                with self.assertRaisesRegex(ValueError, 'fresh_child_namespace'):
                    namespace_case('unreserved', 11)
                command.assert_not_called()
                write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
