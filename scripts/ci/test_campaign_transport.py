#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned API/archive stand-ins; no GitHub/token/network dependency."""
import hashlib
import io
import json
import stat
import unittest
from urllib.error import HTTPError
import zipfile

from campaign_transport import (EvidenceError, GitHubEvidenceClient, JSON_BYTES,
                                artifact_json, strict_json)


def capsule(entries=None):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, raw in entries or [('ci-evidence-summary.json', b'{"owned":true}')]:
            archive.writestr(name, raw)
    raw = result.getvalue()
    return raw, 'sha256:' + hashlib.sha256(raw).hexdigest()


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, req, timeout):
        self.requests.append((req, timeout))
        value = next(self.responses)
        if isinstance(value, BaseException):
            raise value
        return Response(value)


class CampaignTransport(unittest.TestCase):
    def test_exact_single_json_archive_and_digest(self):
        raw, digest = capsule()
        data, member_digest = artifact_json(raw, digest, 'ci-evidence-summary.json')
        self.assertEqual(data, {'owned': True})
        self.assertEqual(member_digest, hashlib.sha256(b'{"owned":true}').hexdigest())

    def test_archive_rejects_changed_bytes_inventory_paths_types_and_expansion(self):
        for scenario in ['digest', 'missing-digest', 'second-member', 'duplicate', 'traversal', 'symlink', 'oversize', 'trailing', 'comment', 'empty-json', 'private-field-duplicate']:
            with self.subTest(scenario=scenario):
                entries = [('ci-evidence-summary.json', b'{}')]
                if scenario == 'second-member':
                    entries.append(('private.txt', b'private-synthetic'))
                elif scenario == 'duplicate':
                    entries.append(entries[0])
                elif scenario == 'traversal':
                    entries[0] = ('../ci-evidence-summary.json', b'{}')
                elif scenario == 'oversize':
                    entries[0] = ('ci-evidence-summary.json', b' ' * (JSON_BYTES + 1))
                elif scenario == 'empty-json':
                    entries[0] = ('ci-evidence-summary.json', b'')
                elif scenario == 'private-field-duplicate':
                    entries[0] = ('ci-evidence-summary.json', b'{"a":1,"a":"private-synthetic"}')
                elif scenario == 'symlink':
                    info = zipfile.ZipInfo('ci-evidence-summary.json')
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o600) << 16
                    entries[0] = (info, b'{}')
                raw, digest = capsule(entries)
                if scenario == 'digest':
                    digest = 'sha256:' + '0' * 64
                elif scenario == 'missing-digest':
                    digest = None
                elif scenario in ('trailing', 'comment'):
                    raw += b'private-synthetic'
                    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
                with self.assertRaises(EvidenceError):
                    artifact_json(raw, digest, 'ci-evidence-summary.json')

    def test_json_bounds_duplicate_fields_utf8_numbers_and_string_braces(self):
        self.assertEqual(strict_json(b'{"owned":"[[[{\\\"x"}'), {'owned': '[[[{"x'})
        for raw in [b'{"a":0,"a":1}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff',
                    b'[' * 65 + b'0' + b']' * 65, b' ' * (JSON_BYTES + 1), b'{}{}']:
            with self.subTest(length=len(raw)):
                with self.assertRaises(EvidenceError):
                    strict_json(raw)

    def test_api_redirect_strips_token_and_uses_fixed_endpoint(self):
        target = 'https://owned.blob.core.windows.net/evidence?sig=private-synthetic'
        redirect = HTTPError('https://api.github.com/owned', 302, 'found', {'Location': target}, io.BytesIO())
        opener = Opener([redirect, b'owned'])
        client = GitHubEvidenceClient('owned-synthetic-token', opener=opener)
        self.assertEqual(client.get('artifacts/1/zip', redirect=True), b'owned')
        first, second = [r[0] for r in opener.requests]
        self.assertEqual(first.full_url, 'https://api.github.com/repos/ctlplne/cratectl/actions/artifacts/1/zip')
        self.assertEqual(first.get_header('Authorization'), 'Bearer owned-synthetic-token')
        self.assertIsNone(second.get_header('Authorization'))
        self.assertEqual(second.full_url, target)
        self.assertTrue(all(timeout == 15 for _, timeout in opener.requests))

    def test_redirect_refuses_unreviewed_routes_hosts_schemes_and_chains(self):
        for target in ['http://owned.blob.core.windows.net/a', 'https://evil.invalid/a',
                       'https://blob.core.windows.net.evil.invalid/a',
                       'https://token@owned.blob.core.windows.net/a',
                       'https://owned.blob.core.windows.net:444/a',
                       'https://owned.blob.core.windows.net/a#secret', 'x' * 8193]:
            with self.subTest(target=target[:45]):
                opener = Opener([HTTPError('owned', 302, 'found', {'Location': target}, io.BytesIO())])
                with self.assertRaises(EvidenceError):
                    GitHubEvidenceClient('owned', opener).get('jobs/1/logs', redirect=True)
                self.assertEqual(len(opener.requests), 1)
        opener = Opener([HTTPError('owned', 302, 'found', {'Location': 'https://owned.actions.githubusercontent.com/a'}, io.BytesIO()),
                         HTTPError('owned', 302, 'found', {}, io.BytesIO())])
        with self.assertRaisesRegex(EvidenceError, '^api_request_failed$'):
            GitHubEvidenceClient('owned', opener).get('jobs/1/logs', redirect=True)

    def test_api_inventory_byte_time_request_and_total_limits(self):
        for body in [b'{"total_count":2,"jobs":[{}]}', b'{"total_count":101,"jobs":[]}', b'{"total_count":true,"jobs":[{}]}']:
            with self.assertRaisesRegex(EvidenceError, '^api_inventory_limit$'):
                GitHubEvidenceClient('owned', Opener([body])).listing('runs/1/jobs?per_page=100', 'jobs')
        client = GitHubEvidenceClient('owned', Opener([b'12345']))
        with self.assertRaisesRegex(EvidenceError, '^response_byte_limit$'):
            client.get('jobs/1/logs', maximum=4)
        client = GitHubEvidenceClient('owned', Opener([b'12']))
        client.remaining = 1
        with self.assertRaisesRegex(EvidenceError, '^response_byte_limit$'):
            client.get('jobs/1/logs')
        client = GitHubEvidenceClient('owned', Opener([]))
        client.requests = 200
        with self.assertRaisesRegex(EvidenceError, '^request_limit$'):
            client.get('jobs/1/logs')
        opener = Opener([HTTPError('owned', 302, 'found', {'Location': 'https://owned.actions.githubusercontent.com/a'}, io.BytesIO())])
        client = GitHubEvidenceClient('owned', opener)
        client.requests = 199
        with self.assertRaisesRegex(EvidenceError, '^request_limit$'):
            client.get('jobs/1/logs', redirect=True)
        self.assertEqual(len(opener.requests), 1)
        clock = iter([0, 0, 0, 61])
        client = GitHubEvidenceClient('owned', Opener([b'owned']), clock=lambda: next(clock))
        with self.assertRaisesRegex(EvidenceError, '^response_time_limit$'):
            client.get('jobs/1/logs')

    def test_invalid_api_route_never_sends_token_and_errors_omit_response(self):
        opener = Opener([])
        client = GitHubEvidenceClient('owned-synthetic-token', opener)
        for route in ['https://evil.invalid', '../secrets', 'jobs/0/logs', 'jobs/1/logs?token=owned', 'runs/1/jobs?per_page=100&page=2']:
            with self.assertRaisesRegex(EvidenceError, '^api_route$'):
                client.get(route)
        self.assertEqual(opener.requests, [])
        opener = Opener([HTTPError('private-synthetic', 500, 'private-synthetic', {}, io.BytesIO(b'private-synthetic'))])
        with self.assertRaisesRegex(EvidenceError, '^api_request_failed$'):
            GitHubEvidenceClient('owned', opener).get('jobs/1/logs')


if __name__ == '__main__':
    unittest.main()
