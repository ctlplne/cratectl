#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Privacy and first-error boundaries for native-client diagnostic export."""
import unittest

from native_client_diagnostics import CODES, safe_client_diagnostics


class NativeDiagnostics(unittest.TestCase):
    def test_nested_error_retains_only_reviewed_codes(self):
        raw = b'Error: get credentials: reading JSON file "/private/synthetic": permission denied; token=private-synthetic-value\n'
        codes = safe_client_diagnostics(raw)
        self.assertEqual(codes, ['credential_read', 'permission_denied'])
        self.assertNotIn('private-synthetic-value', repr(codes))
        self.assertNotIn('/private', repr(codes))

    def test_first_error_is_not_replaced_by_later_source_or_body(self):
        raw = b'Error: pinging container registry private-synthetic-value: invalid status code from registry 403\n\n' + b'context\n' * 4 + b'source mentions unknown flag: and manifest unknown\n'
        self.assertEqual(safe_client_diagnostics(raw), ['registry_ping', 'registry_status'])
        self.assertEqual(safe_client_diagnostics(b'warning private-synthetic-value\n' * 10000 + raw), ['registry_ping', 'registry_status'])

    def test_unknown_and_secret_only_output_exports_no_text(self):
        for raw in [b'', b'private-synthetic-value', b'Bearer private-synthetic-value\n/path/private\nhttps://user:private-synthetic-value@private.invalid']:
            self.assertEqual(safe_client_diagnostics(raw), [])
        for raw in ['private-synthetic-value', b'x' * ((8 << 20) + 1)]:
            with self.assertRaises(ValueError):
                safe_client_diagnostics(raw)
        self.assertLessEqual(len(CODES), 40)

    def test_observed_podman4_runroot_failure_has_a_fixed_code(self):
        self.assertEqual(safe_client_diagnostics(b'Error: the specified runroot is longer than 50 characters\n'), ['runtime_path_limit'])


if __name__ == '__main__':
    unittest.main()
