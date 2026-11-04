#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Real CMS round trips, authentication failures and owned-file collection."""
import base64
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

from ci_native_diagnostics import collect, collect_jvm, collect_console, seal, unseal, write_new

ROOT = Path(__file__).resolve().parents[1]


class EncryptedNativeDiagnostics(unittest.TestCase):
    def test_console_timeout_collects_only_owned_logs_without_a_final_report(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-browser-cms-',dir=self.folder) as temp:
            root=Path(temp);subprocess.run(['git','init','-q','-b','main',str(root)],check=True)
            evidence=root/'evidence/2026-11-04';evidence.mkdir(parents=True)
            folder=root/'.private/console-conformance'/('3'*10);folder.mkdir(parents=True)
            (folder/'commands.log').write_bytes(b'owned private partial Playwright output')
            (folder/'registry.log').write_bytes(b'owned registry output')
            for name in ['admin.token','browser-fixture.json','database.json']:
                (folder/name).write_text('private-synthetic-credential-value')
            report={'candidate':'a'*40,'run':'3'*10,'workflow':'all','status':'failed','failure':'TimeoutError: owned browser suite exceeded 300 seconds','credential':'private-synthetic-credential-value'}
            path=evidence/('console-'+'3'*10+'.json');path.write_text(json.dumps(report))
            failures=collect_console(root,'a'*40);self.assertEqual(len(failures),1)
            self.assertEqual(failures[0]['error'],report['failure'])
            self.assertEqual([v['name'] for v in failures[0]['logs']],['commands.log','registry.log'])
            self.assertEqual(base64.b64decode(failures[0]['logs'][0]['output_base64']),b'owned private partial Playwright output')
            self.assertNotIn('private-synthetic-credential-value',json.dumps(failures))
            (folder/'browser-results.json').write_text('{"owned":"final failure"}')
            self.assertEqual(len(collect_console(root,'a'*40)[0]['logs']),3)
            with self.assertRaises(ValueError):collect_console(root,'b'*40)
            report['status']='passed';path.write_text(json.dumps(report));self.assertEqual(collect_console(root,'a'*40),[])
            report['status']='failed';path.write_text(json.dumps(report))
            (folder/'commands.log').unlink();(folder/'commands.log').symlink_to(folder/'admin.token')
            with self.assertRaises(ValueError):collect_console(root,'a'*40)

    @classmethod
    def setUpClass(cls):
        observed = subprocess.run(['openssl', 'version'], capture_output=True, text=True, timeout=10)
        version = re.match(r'(OpenSSL|LibreSSL) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})\b', observed.stdout)
        if observed.returncode or version is None or version[1] != 'OpenSSL' or int(version[2].split('.')[0]) < 3:
            public = (version[1] + ' ' + version[2]) if version else 'unrecognized CLI'
            raise AssertionError('CMS fixtures require native OpenSSL3or later; observed ' + public)
        cls.temporary = tempfile.TemporaryDirectory(prefix='cratectl-cms-', dir=ROOT / '.cache')
        cls.folder = Path(cls.temporary.name)
        cls.key, cls.cert = cls.folder / 'recipient.key', cls.folder / 'recipient.pem'
        completed = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1', '-subj', '/CN=cratectl-synthetic-ci-test', '-keyout', str(cls.key), '-out', str(cls.cert)], capture_output=True, timeout=30)
        if completed.returncode:
            raise AssertionError('real OpenSSL recipient fixture could not be generated')
        cls.wrong_key = cls.folder / 'wrong.key'
        completed = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.wrong_key)], capture_output=True, timeout=30)
        if completed.returncode:
            raise AssertionError('real wrong-key fixture could not be generated')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_authenticated_roundtrip_and_tamper_rejection(self):
        raw = b'private-synthetic-value\x00\xff\n' * 100
        ciphertext = seal(raw, self.cert)
        self.assertNotIn(raw[:23], ciphertext)
        self.assertEqual(unseal(ciphertext, self.key, self.cert), raw)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        for bad in (bytes(tampered), ciphertext[:-1], b'not CMS'):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                unseal(bad, self.key, self.cert)
        with self.assertRaises(ValueError):
            unseal(ciphertext, self.wrong_key, self.cert)
        with self.assertRaises(ValueError):
            seal(raw, self.folder / 'missing.pem')

    def test_collection_selects_failed_owned_logs_and_excludes_credentials(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-cms-input-', dir=self.folder) as temp:
            root = Path(temp)
            folder = root / '.private/oci-client-conformance' / ('1' * 10)
            folder.mkdir(parents=True)
            log = folder / ('command-' + '2' * 32 + '.log')
            log.write_bytes(b'private-synthetic-command-error')
            (folder / 'admin.token').write_text('private-synthetic-credential-value')
            (folder / 'registry.log').write_bytes(b'private-synthetic-registry-error')
            command = {'label': 'owned command', 'private_log': str(log.relative_to(root)), 'expected_success': True, 'exit': 1}
            report = {'candidate': 'a' * 40, 'run': '1' * 10, 'status': 'failed', 'phase': 'authentication', 'commands': [command, {**command, 'expected_success': False}], 'credential': 'private-synthetic-credential-value'}
            progress = folder / 'progress.json'
            progress.write_text(json.dumps(report))
            payload, count = collect(root, 'a' * 40)
            self.assertEqual(count, 1)
            data = json.loads(payload)
            commands = data['failures'][0]['commands']
            self.assertEqual(len(commands), 1)
            self.assertEqual(base64.b64decode(commands[0]['output_base64']), log.read_bytes())
            self.assertNotIn('private-synthetic-credential-value', payload.decode())
            progress.write_text(json.dumps({**report, 'commands': [{**command, 'exit': 0}], 'last_observation': {**command, 'exit': 0}, 'failure': 'owned post-command assertion'}))
            observed, count = collect(root, 'a' * 40)
            failure = json.loads(observed)['failures'][0]
            self.assertTrue(failure['commands'][0]['observation_only'])
            self.assertEqual(failure['commands'][0]['exit'], 0)
            self.assertEqual(failure['error'], 'owned post-command assertion')
            progress.write_text(json.dumps(report))
            log.unlink()
            log.symlink_to(folder / 'admin.token')
            with self.assertRaises(ValueError):
                collect(root, 'a' * 40)
            with self.assertRaises(ValueError):
                collect(root, 'b' * 40)

    def test_private_outputs_cannot_replace_existing_files_or_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-cms-output-', dir=self.folder) as temp:
            path = Path(temp) / 'output'
            write_new(Path(temp), path, b'private-synthetic-value')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_new(Path(temp), path, b'replacement')
            link = Path(temp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                write_new(Path(temp), link, b'replacement')
            self.assertEqual(path.read_bytes(), b'private-synthetic-value')
            parent = Path(temp) / 'escaped'
            parent.symlink_to(self.folder, target_is_directory=True)
            with self.assertRaises(OSError):
                write_new(Path(temp), parent / 'must-not-exist', b'replacement')

    def test_jvm_collection_uses_generated_failed_observations_and_excludes_credentials(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-jvm-cms-',dir=self.folder) as temp:
            root=Path(temp);subprocess.run(['git','init','-q','-b','main',str(root)],check=True)
            evidence=root/'evidence/2026-11-04';evidence.mkdir(parents=True)
            private=root/'.private/conformance'/('1'*10);private.mkdir(parents=True)
            (private/'reader.token').write_text('private-synthetic-credential-value')
            (private/'server.log').write_text('owned registry observation')
            report={'candidate':'a'*40,'run':'1'*10,'status':'failed','ivy_contract':{},'failure':'owned post-command assertion',
                    'credential':'private-synthetic-credential-value','commands':[{'exit':0,'output':'earlier unused observation'},
                    {'exit':1,'expected_failure':True,'output':'expected policy denial'}, {'exit':0,'output':'Apache Ant(TM) version 1.10.14'}]}
            path=evidence/('conformance-'+'1'*10+'.json');path.write_text(json.dumps(report))
            tracked=evidence/('conformance-'+'2'*10+'.json');tracked.write_text(json.dumps({**report,'candidate':'b'*40}))
            subprocess.run(['git','add',str(tracked.relative_to(root))],cwd=root,check=True)
            failures=collect_jvm(root,'a'*40);self.assertEqual(len(failures),1)
            commands=failures[0]['commands'];self.assertEqual(len(commands),1)
            self.assertTrue(commands[0]['observation_only'])
            self.assertEqual(base64.b64decode(commands[0]['output_base64']),b'Apache Ant(TM) version 1.10.14')
            self.assertNotIn('private-synthetic-credential-value',json.dumps(failures))
            self.assertNotIn('earlier unused observation',json.dumps(failures))
            report['commands'].append({'exit':1,'expected_failure':False,'output':'owned actual failure'})
            path.write_text(json.dumps(report));observed=collect_jvm(root,'a'*40)[0]['commands']
            self.assertFalse(observed[0]['observation_only'])
            self.assertEqual(base64.b64decode(observed[0]['output_base64']),b'owned actual failure')
            # Only ciphertext may leave the runner; authenticated local decode
            # retains the same exact selected output without credential fields.
            payload=json.dumps(collect_jvm(root,'a'*40)).encode()
            self.assertEqual(unseal(seal(payload,self.cert),self.key,self.cert),payload)
            sbt_report={k:v for k,v in report.items() if k!='ivy_contract'}
            sbt_report['sbt_contract']={'series':'sbt1'}
            path.write_text(json.dumps(sbt_report));sbt_failure=collect_jvm(root,'a'*40)[0]
            self.assertEqual(sbt_failure['client'],'sbt')
            self.assertNotIn('private-synthetic-credential-value',json.dumps(sbt_failure))
            self.assertEqual(base64.b64decode(sbt_failure['commands'][0]['output_base64']),b'owned actual failure')
            with self.assertRaises(ValueError):collect_jvm(root,'b'*40)
            path.unlink();path.symlink_to(private/'reader.token')
            with self.assertRaises(ValueError):collect_jvm(root,'a'*40)

    def test_jvm_collection_rejects_unbounded_or_malformed_generated_reports(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-jvm-cms-bounds-',dir=self.folder) as temp:
            root=Path(temp);subprocess.run(['git','init','-q','-b','main',str(root)],check=True)
            evidence=root/'evidence/2026-11-04';evidence.mkdir(parents=True)
            path=evidence/('conformance-'+'1'*10+'.json')
            report={'candidate':'a'*40,'run':'1'*10,'status':'failed','gradle_contract':{},'commands':[{'exit':1,'output':'owned failure'}]}
            changes=[[],{**report,'run':'../wrong'},{**report,'commands':[{'exit':1,'output':'x'*12001}]},
                     {**report,'commands':[{'exit':1,'output':'failure'}]*3},{**report,'commands':[{}]*1025},
                     {**report,'ivy_contract':{}},{**report,'sbt_contract':{}},{**report,'failure':'x'*8193}]
            for change in changes:
                path.write_text(json.dumps(change))
                with self.subTest(change_type=type(change).__name__),self.assertRaises(ValueError):collect_jvm(root,'a'*40)


if __name__ == '__main__':
    unittest.main()
