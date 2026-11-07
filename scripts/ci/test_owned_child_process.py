# SPDX-License-Identifier: BUSL-1.1
"""Filesystem/proc stand-ins: these tests never signal any actual process."""
from pathlib import Path
import tempfile
import unittest

from owned_child_process import validate_owned_cli


class IdentityTests(unittest.TestCase):
    def fixture(self, directory):
        proc = Path(directory) / 'proc'
        executable = Path(directory) / 'owned-cli'
        executable.write_bytes(b'inert executable identity stand-in')
        for pid, parent in [(300, 200), (200, 100), (100, 50)]:
            path = proc / str(pid)
            (path / 'ns').mkdir(parents=True)
            (path / 'status').write_text('Name:\tcratectl-owned\nUid:\t1001\t1001\t1001\t1001\nPPid:\t%d\n' % parent)
            (path / 'exe').symlink_to(executable)
            (path / 'ns/net').write_bytes(b'owned namespace stand-in')
        return proc, executable, (proc / '300/ns/net').stat().st_ino

    def test_exact_cli_descendant_and_direct_launcher_accept_without_signalling(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-owned-pid-') as directory:
            proc, binary, ns = self.fixture(directory)
            self.assertEqual(validate_owned_cli(300, 100, binary, 1001, ns, proc), 300)
            self.assertEqual(validate_owned_cli(300, 300, binary, 1001, ns, proc), 300)

    def test_wrapper_pid_cannot_substitute_for_actual_executable(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-owned-pid-') as directory:
            proc, binary, ns = self.fixture(directory)
            wrapper = Path(directory) / 'owned-launcher'
            wrapper.write_bytes(b'inert launcher identity')
            (proc / '200/exe').unlink()
            (proc / '200/exe').symlink_to(wrapper)
            with self.assertRaises(ValueError):
                validate_owned_cli(200, 100, binary, 1001, (proc / '200/ns/net').stat().st_ino, proc)
            self.assertEqual(validate_owned_cli(300, 100, binary, 1001, ns, proc), 300)

    def test_wrong_uid_namespace_parent_cycle_and_unknown_launcher_refuse(self):
        for mode in ['uid', 'namespace', 'cycle', 'unrelated']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='cratectl-owned-pid-') as directory:
                proc, binary, ns = self.fixture(directory)
                launcher = 100
                if mode == 'uid':
                    text = (proc / '300/status').read_text().replace('1001', '1002')
                    (proc / '300/status').write_text(text)
                if mode == 'namespace':
                    ns += 1
                if mode == 'cycle':
                    (proc / '200/status').write_text('Uid:\t1001\t1001\t1001\t1001\nPPid:\t300\n')
                if mode == 'unrelated':
                    launcher = 999
                with self.assertRaises(ValueError):
                    validate_owned_cli(300, launcher, binary, 1001, ns, proc)

    def test_incomplete_duplicate_and_oversized_status_refuse(self):
        for raw in [b'Uid:\t1001\nPPid:\t200\n', b'Uid:\t1001\t1001\t1001\t1001\nPPid:\t200\nPPid:\t200\n', b'x' * ((16 << 10) + 1)]:
            with tempfile.TemporaryDirectory(prefix='cratectl-owned-pid-') as directory:
                proc, binary, ns = self.fixture(directory)
                (proc / '300/status').write_bytes(raw)
                with self.assertRaises(ValueError):
                    validate_owned_cli(300, 100, binary, 1001, ns, proc)


if __name__ == '__main__':
    unittest.main()
