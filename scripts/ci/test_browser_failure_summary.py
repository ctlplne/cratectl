#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Browser diagnostics expose known focus labels, never raw locator/error text."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import browser_failure_summary as diagnostics
from browser_failure_summary import safe_axe_findings, safe_error_kind, safe_focus_target, safe_go_export_progress, safe_nuget_progress


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

    def test_nuget_progress_exports_fixed_phase_and_count_only(self):
        proof = {'phase': 'exact_review', 'checks': ['private-synthetic-value'], 'private_error': 'private-synthetic-value'}
        self.assertEqual(safe_nuget_progress(proof), ['NuGet workflow phase: exact_review', 'NuGet workflow progress: 1 completed checks'])
        self.assertNotIn('private-synthetic-value', '\n'.join(safe_nuget_progress(proof)))
        self.assertEqual(safe_nuget_progress({'phase': 'private-synthetic-value', 'checks': ['secret'] * 33}), [])

    def test_export_scroll_failure_reports_only_reviewed_state_rule_and_counts(self):
        proof = {'phase': 'import-command', 'checks': ['private-synthetic-value'], 'raw_message': 'private-synthetic-value',
                 'accessibility': [{'state': 'export explicit destination import instructions', 'findings': [
                     {'id': 'scrollable-region-focusable', 'impact': 'serious', 'nodes': 1,
                      'html': 'private-synthetic-value', 'target': ['private-synthetic-value']},
                     {'id': 'private/value', 'impact': 'serious', 'nodes': 1}]}]}
        self.assertEqual(safe_go_export_progress(proof), ['Hosted export workflow phase: import-command',
                         'Hosted export workflow progress: 1 completed checks',
                         'Hosted export accessibility finding: export explicit destination import instructions: rule=scrollable-region-focusable impact=serious nodes=1'])
        self.assertNotIn('private-synthetic-value', '\n'.join(safe_go_export_progress(proof)))
        self.assertEqual(safe_go_export_progress({'phase': 'private-synthetic-value', 'checks': ['secret'] * 33}), [])

    def test_malformed_accessibility_arrays_never_echo_or_crash(self):
        for proof in [None, {'accessibility': {}}, {'accessibility': [None]},
                      {'accessibility': [{'state': 'repair awaiting source', 'findings': 'private-synthetic'}]}, {'accessibility': [{'state': [], 'findings': []}]}, {'accessibility': [{'state': 'repair awaiting source', 'findings': [{'id': [], 'impact': 'serious', 'nodes': 1}]}]}]:
            self.assertEqual(safe_axe_findings(proof), [])

    def test_result_without_error_body_keeps_safe_location_and_unclassified_kind(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-browser-summary-') as directory:
            root = Path(directory)
            folder = root / '.private/console-conformance/owned'
            folder.mkdir(parents=True)
            report = {'stats': {'expected': 0, 'unexpected': 1, 'skipped': 0, 'flaky': 0},
                      'suites': [{'specs': [{'file': 'go-exports.spec.mjs', 'line': 7,
                                            'tests': [{'status': 'unexpected', 'results': [
                                                {'status': 'failed', 'retry': 0, 'errors': [], 'error': 'private-synthetic-value'}]}]}]}]}
            (folder / 'browser-results.json').write_text(json.dumps(report))
            output = io.StringIO()
            with patch.object(diagnostics, '__file__', str(root / 'scripts/ci/browser_failure_summary.py')), redirect_stdout(output):
                diagnostics.main()
            self.assertIn('Nonpassing test: go-exports.spec.mjs:7', output.getvalue())
            self.assertIn('error kind: unclassified', output.getvalue())
            self.assertNotIn('private-synthetic-value', output.getvalue())


if __name__ == '__main__':
    unittest.main()
