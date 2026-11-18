#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import json
from pathlib import Path
import tempfile
import unittest

from linux_candidate_sbom import Component, archive_checksums, cyclonedx, linked_modules, locked_web_modules, spdx


class LinuxCandidateSBOMTests(unittest.TestCase):
    def test_binds_modules_and_refuses_replacements_or_unrecorded_hashes(self):
        name, version, checksum = 'golang.org/x/example', 'v1.2.3', 'h1:' + 'a' * 43 + '='
        manifest = {'platform': 'linux/arm64', 'candidate': '1' * 40, 'go_version': '1.27.4'}
        settings = {'vcs.revision': manifest['candidate'], 'vcs.modified': 'false',
                    'GOOS': 'linux', 'GOARCH': 'arm64', 'CGO_ENABLED': '0'}
        entry = {'Path': name, 'Version': version, 'Sum': checksum}
        info = {'Path': 'ctlplne.dev/cratectl/cmd/cratectl', 'GoVersion': 'go1.27.4',
                'Main': {'Path': 'ctlplne.dev/cratectl'}, 'Deps': [entry],
                'Settings': [{'Key': key, 'Value': value} for key, value in settings.items()]}
        component, = linked_modules(info, manifest, 'cratectl', {(name, version): checksum}).values()
        self.assertEqual((component.purl, component.source_integrity), ('pkg:golang/golang.org/x/example@v1.2.3', checksum))
        for deps in ([], [entry, entry], [{**entry, 'Replace': {'Path': './local'}}], [{**entry, 'Sum': 'h1:' + 'b' * 43 + '='}]):
            with self.subTest(deps=deps), self.assertRaises(ValueError):
                linked_modules({**info, 'Deps': deps}, manifest, 'cratectl', {(name, version): checksum})
        with self.assertRaises(ValueError):
            linked_modules(info, {**manifest, 'platform': 'linux/amd64'}, 'cratectl', {(name, version): checksum})

    def test_binds_npm_lock_integrity_to_actual_embedded_notices(self):
        checksum = 'sha512-' + 'a' * 86 + '=='
        pin = {'version': '1.2.3', 'integrity': checksum, 'license': 'MIT'}
        names = ('react', 'react-dom', 'scheduler')
        lock = {'packages': {'node_modules/' + name: pin for name in names}}
        notices = '\n'.join('--- ' + name + ' 1.2.3 ---' for name in names)
        self.assertEqual([part.purl for part in locked_web_modules(lock, notices)],
                         ['pkg:npm/' + name + '@1.2.3' for name in names])
        with self.assertRaises(ValueError):
            locked_web_modules(lock, notices.replace('scheduler 1.2.3', 'scheduler 4.5.6'))

    def test_documents_bind_the_same_archive_binaries_and_scoped_dependencies(self):
        sha = 'a' * 64
        artifact = Component('archive', 'cratectl linux/amd64', 'b' * 40, 'application', checksum=sha,
                             filename='cratectl-linux-amd64.tar.gz', license='BUSL-1.1')
        components = [Component('cratectl', 'cratectl', artifact.version, 'application'),
                      Component('cratectld', 'cratectld', artifact.version, 'application'),
                      Component('npm-react', 'react', '1.2.3', 'library', purl='pkg:npm/react@1.2.3')]
        edges = [('archive', 'CONTAINS', 'cratectl'), ('archive', 'CONTAINS', 'cratectld'), ('cratectld', 'CONTAINS', 'npm-react')]
        timestamp = '2026-11-18T00:00:00Z'
        spdx_document = spdx(artifact, components, edges, timestamp)
        cdx_document = cyclonedx(artifact, components, edges, timestamp)
        self.assertEqual(spdx_document['packages'][0]['checksums'], [{'algorithm': 'SHA256', 'checksumValue': sha}])
        self.assertEqual(cdx_document['metadata']['component']['hashes'], [{'alg': 'SHA-256', 'content': sha}])
        self.assertEqual(cdx_document['dependencies'], [
            {'ref': 'archive', 'dependsOn': ['cratectl', 'cratectld']},
            {'ref': 'cratectl', 'dependsOn': []}, {'ref': 'cratectld', 'dependsOn': ['npm-react']}])
        self.assertEqual(len(spdx_document['relationships']), len(edges) + 1)
        self.assertNotIn('vulnerabilities', cdx_document)
        self.assertNotIn('devDependencies', json.dumps(spdx_document))

    def test_requires_exact_canonical_archive_checksum_inventory(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-sbom-checksums-') as folder:
            path = Path(folder) / 'SHA256SUMS'
            names = ('cratectl-linux-amd64.tar.gz', 'cratectl-linux-arm64.tar.gz')
            content = ''.join('3' * 64 + '  ' + name + '\n' for name in names)
            path.write_text(content)
            self.assertEqual(archive_checksums(path), dict.fromkeys(names, '3' * 64))
            for malformed in (content + content, content.rstrip(), content.replace('amd64', 'arm64', 1)):
                path.write_text(malformed)
                with self.assertRaises(ValueError):
                    archive_checksums(path)


if __name__ == '__main__':
    unittest.main()
