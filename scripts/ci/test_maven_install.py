#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise installer failure boundaries with an owned curl stand-in, no network."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MavenInstall(unittest.TestCase):
    def install(self, mode, hosted=True):
        with tempfile.TemporaryDirectory(prefix='cratectl-maven-bootstrap-', dir=ROOT / '.cache') as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            (root / 'docs/qualification').mkdir(parents=True)
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                member = tarfile.TarInfo('apache-maven-3.10.0/owned.txt')
                member.size = 5
                archive.addfile(member, io.BytesIO(b'owned'))
            (root / 'fixture.tar.gz').write_bytes(data.getvalue())
            pins = json.loads((ROOT / 'docs/qualification/jvm-clients.json').read_text())
            pins['maven']['sha512'] = hashlib.sha512(data.getvalue()).hexdigest()
            (root / 'docs/qualification/jvm-clients.json').write_text(json.dumps(pins))
            curl = root / 'bin/curl'
            curl.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
from pathlib import Path
a=sys.argv[1:];p=Path('requests.json');rows=json.loads(p.read_text()) if p.exists() else [];rows.append(a);p.write_text(json.dumps(rows))
destination=Path(a[a.index('--output')+1]);mode=os.environ['CRATECTL_MAVEN_STANDIN']
if mode=='both_fail' or (mode=='fallback' and len(rows)==1):
 destination.write_bytes(b'partial');sys.exit(28)
destination.write_bytes(b'corrupt' if mode=='mismatch' else Path('fixture.tar.gz').read_bytes())
''')
            curl.chmod(0o700)
            # macOS does not necessarily install GNU sha512sum. This stand-in
            # checks the actual requested pin against every downloaded byte.
            checksum = root / 'bin/sha512sum'
            checksum.write_text('#!' + sys.executable + '\n' + '''import hashlib,sys
from pathlib import Path
assert sys.argv[1:]==['--check','--status']
digest,path=sys.stdin.read().strip().split('  ',1)
sys.exit(0 if hashlib.sha512(Path(path).read_bytes()).hexdigest()==digest else 1)
''')
            checksum.chmod(0o700)
            environment = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                               GITHUB_ACTIONS='true' if hosted else 'false', RUNNER_ENVIRONMENT='github-hosted',
                               CRATECTL_MAVEN_STANDIN=mode)
            result = subprocess.run(['bash', str(ROOT / 'scripts/ci/install_maven.sh')], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=15)
            requests = json.loads((root / 'requests.json').read_text()) if (root / 'requests.json').exists() else []
            for request in requests:
                for option, expected in [('--proto', '=https'), ('--proto-redir', '=https'),
                                         ('--connect-timeout', '15'), ('--max-time', '180'),
                                         ('--max-filesize', '33554432')]:
                    self.assertEqual(request[request.index(option) + 1], expected)
            return result.returncode, requests, (root / '.cache/apache-maven-3.10.0/owned.txt').exists(), list((root / '.cache').glob('*.part'))

    def test_primary_download_is_checked_and_extracted(self):
        code, requests, extracted, partial = self.install('primary')
        self.assertEqual((code, len(requests), extracted, partial), (0, 1, True, []))
        self.assertTrue(requests[0][-1].startswith('https://downloads.apache.org/'))

    def test_transport_failure_uses_only_approved_archive(self):
        code, requests, extracted, partial = self.install('fallback')
        self.assertEqual((code, len(requests), extracted, partial), (0, 2, True, []))
        self.assertTrue(requests[1][-1].startswith('https://archive.apache.org/dist/maven/'))

    def test_digest_mismatch_never_falls_back_or_extracts(self):
        code, requests, extracted, _ = self.install('mismatch')
        self.assertNotEqual(code, 0)
        self.assertEqual((len(requests), extracted), (1, False))

    def test_exhausted_transfers_leave_no_partial_or_installation(self):
        code, requests, extracted, partial = self.install('both_fail')
        self.assertNotEqual(code, 0)
        self.assertEqual((len(requests), extracted, partial), (2, False, []))

    def test_nonhosted_execution_stops_before_network(self):
        code, requests, extracted, partial = self.install('primary', hosted=False)
        self.assertNotEqual(code, 0)
        self.assertEqual((requests, extracted, partial), ([], False, []))


if __name__ == '__main__':
    unittest.main()
