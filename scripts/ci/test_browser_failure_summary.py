#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Browser diagnostics expose known focus labels, never raw locator/error text."""
import unittest
from browser_failure_summary import safe_focus_target


class SafeFocusTarget(unittest.TestCase):
    def test_known_focus_labels_produce_only_fixed_identifiers(self):
        for label, expected in [('Repair reason', 'repair_reason'), ('Verified repair source file', 'verified_source')]:
            private_message = f'Error: expect(locator).toBeFocused() failed; getByLabel({label!r}); private-synthetic-value'
            self.assertEqual(safe_focus_target(private_message), expected)
            self.assertNotIn('private-synthetic-value', safe_focus_target(private_message))

    def test_unknown_error_content_is_not_echoed(self):
        self.assertEqual(safe_focus_target('private-synthetic-value'), 'unknown')


if __name__ == '__main__':
    unittest.main()
