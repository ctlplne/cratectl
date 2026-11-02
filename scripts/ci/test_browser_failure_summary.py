#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Browser diagnostics expose known focus labels, never raw locator/error text."""
import unittest
from browser_failure_summary import safe_axe_findings, safe_error_kind, safe_focus_target


class SafeFocusTarget(unittest.TestCase):
    def test_error_header_wins_over_unrelated_matchers_in_source_frames(self):
        message = 'Error: response.json: Protocol error (Network.getResponseBody): No data found\n  31 | expect(field).toBeFocused(); expect(violations).toEqual([])'
        self.assertEqual(safe_error_kind(message), 'response_body')
        self.assertEqual(safe_error_kind('Error: locator.click: Error: strict mode violation\nexpect(x).toBeFocused()'), 'locator_ambiguous')
        self.assertEqual(safe_error_kind('Error: expect(locator).toBeFocused() failed'), 'assert_focus')

    def test_known_focus_labels_produce_only_fixed_identifiers(self):
        for label, expected in [('Repair reason', 'repair_reason'), ('Verified repair source file', 'verified_source')]:
            private_message = f'Error: expect(locator).toBeFocused() failed; getByLabel({label!r}); private-synthetic-value'
            self.assertEqual(safe_focus_target(private_message), expected)
            self.assertNotIn('private-synthetic-value', safe_focus_target(private_message))

    def test_unknown_error_content_is_not_echoed(self):
        self.assertEqual(safe_focus_target('private-synthetic-value'), 'unknown')

    def test_accessibility_diagnostics_keep_rule_counts_and_drop_dom_content(self):
        proof = {'accessibility': [{'state': 'repair awaiting source', 'findings': [
            {'id': 'label', 'impact': 'critical', 'nodes': 1, 'html': 'private-synthetic-value'},
            {'id': 'private/value', 'impact': 'critical', 'nodes': 1},
        ]}, {'state': 'private-synthetic-value', 'findings': [{'id': 'label', 'impact': 'critical', 'nodes': 1}]}]}
        self.assertEqual(safe_axe_findings(proof), ['repair awaiting source: rule=label impact=critical nodes=1'])


if __name__ == '__main__':
    unittest.main()
