#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned curl stand-in and real child file limits, without network or tool execution."""
import hashlib
import errno
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import fetch_archive

ROOT = Path(__file__).resolve().parents[2]
FETCH = ROOT / 'scripts/ci/fetch_archive.py'
ORAS = 'oras_1.3.6_linux_arm64.tar.gz'
ORAS_URL = 'https://github.com/oras-project/oras/releases/download/v1.3.6/' + ORAS
PAYLOAD = b'owned pinned tool archive stand-in'


class FetchArchive(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cratectl-archive-fetch-', dir=ROOT/'.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root/'bin').mkdir()
        (self.root/'payload').write_bytes(PAYLOAD)
        curl = self.root/'bin/curl'
        curl.write_text('#!' + sys.executable + '\n' + '''import json,os,resource,sys,time
from pathlib import Path
a=sys.argv[1:];p=Path('requests.json');rows=json.loads(p.read_text()) if p.exists() else [];rows.append(a);p.write_text(json.dumps(rows))
destination=Path(a[a.index('--output')+1]);mode=os.environ['CRATECTL_ARCHIVE_STANDIN']
if mode=='overflow':
 try:destination.write_bytes(b'x'*(int(a[a.index('--max-filesize')+1])+1))
 except OSError as error:
  Path('kernel.json').write_text(json.dumps({'bytes':destination.stat().st_size,'errno':error.errno,'limits':resource.getrlimit(resource.RLIMIT_FSIZE)}));sys.exit(1)
elif mode=='hang':
 destination.write_bytes(b'partial');time.sleep(30)
elif mode=='transport':
 destination.write_bytes(b'partial');sys.exit(28)
elif mode=='http':
 destination.write_bytes(b'partial');print('private-synthetic-value; requested URL returned error: 503',file=sys.stderr);sys.exit(22)
else:
 destination.write_bytes(b'corrupt' if mode=='mismatch' else Path('payload').read_bytes())
''')
        curl.chmod(0o700)

    def environment(self, mode, hosted=True):
        environment = dict(os.environ, PATH=str(self.root/'bin')+os.pathsep+os.environ['PATH'],
                           GITHUB_ACTIONS='true' if hosted else 'false', RUNNER_ENVIRONMENT='github-hosted',
                           RUNNER_OS='Linux', CRATECTL_ARCHIVE_STANDIN=mode,
                           BASH_ENV=str(self.root/'must-not-load'), POSIXLY_CORRECT='1')
        (self.root/'must-not-load').write_text('exit 99\n')
        return environment

    def run_fetch(self, mode='good', *, archive=ORAS, url=ORAS_URL, digest=None, maximum='4096', hosted=True):
        return subprocess.run([sys.executable, str(FETCH), '--archive', archive, '--url', url,
                               '--sha256', digest if digest is not None else hashlib.sha256(PAYLOAD).hexdigest(),
                               '--max-bytes', maximum], cwd=self.root, env=self.environment(mode,hosted),
                              capture_output=True, text=True, timeout=15)

    def requests(self):
        path=self.root/'requests.json'
        return json.loads(path.read_text()) if path.exists() else []

    def assert_no_partial(self):
        self.assertEqual(list((self.root/'.cache').glob('*.part')), [])

    def test_approved_sources_are_bounded_pinned_and_published_without_executing_payload(self):
        for archive,url in [(ORAS,ORAS_URL),('helm-v4.3.1-linux-arm64.tar.gz','https://get.helm.sh/helm-v4.3.1-linux-arm64.tar.gz'),('gitleaks_8.30.1_linux_x64.tar.gz','https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz')]:
            result=self.run_fetch(archive=archive,url=url)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('(downloaded)',result.stdout)
            self.assertEqual((self.root/'.cache'/archive).read_bytes(),PAYLOAD)
            self.assertEqual((self.root/'.cache'/archive).stat().st_mode&0o777,0o600)
        for request in self.requests():
            self.assertEqual(request[0],'--disable')
            for key,value in [('--proto','=https'),('--proto-redir','=https'),('--max-redirs','5'),
                              ('--connect-timeout','15'),('--max-time','180'),('--max-filesize','4096')]:
                self.assertEqual(request[request.index(key)+1],value)
        self.assert_no_partial()

    def test_gitleaks_source_version_architecture_and_cap_cannot_expand_implicitly(self):
        archive='gitleaks_8.30.1_linux_x64.tar.gz'
        url='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/'+archive
        for name,source,maximum in [
            (archive,url,str((32<<20)+1024)),
            (archive.replace('x64','arm64'),url.replace('x64','arm64'),'4096'),
            (archive.replace('8.30.1','8.30.2'),url.replace('8.30.1','8.30.2'),'4096'),
            (archive,url.replace('/gitleaks/gitleaks/','/other/gitleaks/'),'4096'),
        ]:
            with self.subTest(source=source,maximum=maximum):
                self.assertNotEqual(self.run_fetch(archive=name,url=source,maximum=maximum).returncode,0)
        self.assertEqual(self.requests(),[])

    def test_matching_cache_is_reverified_without_another_network_attempt(self):
        self.assertEqual(self.run_fetch().returncode,0)
        result=self.run_fetch('transport')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('(cache-hit)',result.stdout)
        self.assertEqual(len(self.requests()),1)

    def test_corrupt_cache_fails_without_hiding_or_overwriting_the_original(self):
        self.assertEqual(self.run_fetch().returncode,0)
        target=self.root/'.cache'/ORAS;target.write_bytes(b'corrupt retained evidence')
        self.assertNotEqual(self.run_fetch().returncode,0)
        self.assertEqual(len(self.requests()),1)
        self.assertEqual(target.read_bytes(),b'corrupt retained evidence')
        self.assert_no_partial()

    def test_transfer_or_digest_failure_never_publishes_or_leaves_partial_bytes(self):
        for mode in ['transport','mismatch']:
            with self.subTest(mode=mode):
                self.assertNotEqual(self.run_fetch(mode).returncode,0)
                self.assertFalse((self.root/'.cache'/ORAS).exists())
                self.assert_no_partial()

    def test_http_failure_exposes_only_fixed_exit_and_status_without_raw_output(self):
        result=self.run_fetch('http')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('exit 22, HTTP 503',result.stderr)
        self.assertNotIn('private-synthetic-value',result.stdout+result.stderr)
        self.assertFalse((self.root/'.cache'/ORAS).exists())
        self.assert_no_partial()

    def test_real_child_kernel_limit_rejects_an_oversize_writer_and_keeps_parent_limits(self):
        before=resource.getrlimit(resource.RLIMIT_FSIZE)
        result=self.run_fetch('overflow')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE),before)
        observed=json.loads((self.root/'kernel.json').read_text())
        self.assertEqual(observed['errno'],errno.EFBIG)
        self.assertEqual(observed['limits'][0],4096)
        self.assertLessEqual(observed['bytes'],4096)
        self.assertFalse((self.root/'.cache'/ORAS).exists())
        self.assert_no_partial()
        self.assertFalse(any(p.name.startswith('core')for p in self.root.iterdir()))

    def test_outer_deadline_cleans_only_its_owned_partial(self):
        original=fetch_archive.run_owned_client
        def bounded(*args,**kwargs):
            self.assertEqual(kwargs['timeout'],195)
            kwargs['timeout']=.25
            return original(*args,**kwargs)
        with patch('fetch_archive.run_owned_client',side_effect=bounded):
            with self.assertRaisesRegex(ValueError,'deadline'):
                fetch_archive.fetch(self.root,ORAS,ORAS_URL,hashlib.sha256(PAYLOAD).hexdigest(),4096,self.environment('hang'))
        self.assertFalse((self.root/'.cache'/ORAS).exists())
        self.assert_no_partial()

    def test_linked_cache_and_linked_archive_never_read_or_modify_outside_bytes(self):
        outside=self.root/'outside';outside.mkdir();sentinel=outside/'owned';sentinel.write_bytes(b'untouched')
        cache=self.root/'.cache';cache.symlink_to(outside,target_is_directory=True)
        self.assertNotEqual(self.run_fetch().returncode,0)
        cache.unlink();cache.mkdir();(cache/ORAS).symlink_to(sentinel)
        self.assertNotEqual(self.run_fetch().returncode,0)
        (cache/ORAS).unlink();os.mkfifo(cache/ORAS)
        self.assertNotEqual(self.run_fetch().returncode,0)
        self.assertEqual(self.requests(),[])
        self.assertEqual(sentinel.read_bytes(),b'untouched')

    def test_unknown_sources_bad_pins_paths_and_budgets_fail_before_network(self):
        for change in [{'url':ORAS_URL.replace('https:','http:')},{'url':ORAS_URL.replace('github.com','example.invalid')},
                       {'url':ORAS_URL.replace('github.com','a@github.com')},{'url':ORAS_URL+'?private=value'},
                       {'url':ORAS_URL+'#fragment'},{'archive':'../outside'},{'digest':'x'*64},
                       {'maximum':'0'},{'maximum':'1025'},{'maximum':str((64<<20)+1024)}]:
            with self.subTest(change=change):self.assertNotEqual(self.run_fetch(**change).returncode,0)
        self.assertEqual(self.requests(),[])

    def test_nonhosted_guard_has_no_network_or_cache_side_effect(self):
        self.assertNotEqual(self.run_fetch(hosted=False).returncode,0)
        self.assertEqual(self.requests(),[])
        self.assertFalse((self.root/'.cache').exists())


if __name__=='__main__':unittest.main()
