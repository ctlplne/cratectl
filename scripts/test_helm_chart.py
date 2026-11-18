#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / 'deploy/helm/cratectl'
FIXTURE = ROOT / 'deploy/helm/testdata/values.json'


class HelmChartTests(unittest.TestCase):
    def helm(self, *arguments, status=0):
        result = subprocess.run(['helm', *arguments], cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result.stdout

    def render(self, values, status=0):
        return self.helm('template', 'cratectl-chart-check', str(CHART), '--namespace', 'cratectl-chart-check',
                         '-f', str(values), status=status)

    def test_renders_existing_secrets_and_volume_with_scoped_private_worker_copy(self):
        self.helm('lint', str(CHART), '--strict', '-f', str(FIXTURE))
        rendered = self.render(FIXTURE)
        for expected in ('kind: Deployment', 'kind: ConfigMap', 'kind: Service', 'type: ClusterIP',
                         'type: Recreate', 'replicas: 1', 'automountServiceAccountToken: false', 'runAsNonRoot: true',
                         'readOnlyRootFilesystem: true', 'claimName: "cratectl-data"', 'name: "cratectl-database"',
                         'secretName: "cratectl-registry-tls"', 'secretName: "cratectl-database-ca"',
                         'secretName: "cratectl-worker-tokens"', 'path: /health/ready, port: https, scheme: HTTPS',
                         '/var/run/cratectl/worker/tokens/team-a', '/var/run/cratectl/worker/tokens/team-b',
                         '--identity-config-bytes=8192', 'head -c 258', 'umask 077'):
            self.assertIn(expected, rendered)
        for forbidden in ('kind: Secret', 'kind: PersistentVolumeClaim', 'hostPath:', 'hostNetwork:', 'CRATECTL_OWNER_DSN'):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(rendered.count('name: CRATECTL_DSN'), 2)
        self.assertEqual(rendered.count('mountPath: /source-tokens'), 1)

    def test_rejects_mutable_images_cleartext_urls_and_ambiguous_worker_inputs(self):
        source = json.loads(FIXTURE.read_bytes())
        changes = [
            {'image': 'registry.example.invalid/cratectl/cratectld:mutable'},
            {'publicURL': 'http://cratectl.example.invalid:38443'},
            {'worker': {**source['worker'], 'tokenKeys': ['team-a', 'team-a']}},
            {'worker': {**source['worker'], 'tokenKeys': ['../outside']}},
            {'postgres': {**source['postgres'], 'ownerDSN': 'owned-invalid-fixture'}},
        ]
        with tempfile.TemporaryDirectory(prefix='cratectl-helm-test-') as folder:
            settings = Path(folder) / 'values.json'
            for replacement in changes:
                with self.subTest(keys=list(replacement)):
                    settings.write_text(json.dumps({**source, **replacement}))
                    self.render(settings, status=1)
            alternate = copy.deepcopy(source)
            alternate['postgres']['caSecret'] = ''
            settings.write_text(json.dumps(alternate))
            self.assertNotIn('postgres-ca', self.render(settings))


if __name__ == '__main__':
    unittest.main()
