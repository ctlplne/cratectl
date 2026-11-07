#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Stock Go with checksum verification on against owned TLS response stand-ins.

This exercises the client/fixture contract, never cratectl proxy serving or a
real database. Original public signatures are replayed; no signing service runs.
"""
import argparse
import base64
import collections
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.parse
import zipfile

from bounded_client import run_owned_client

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'internal/server/testdata/go-checksum-public.json'
PROGRESS = {'controls': {}, 'zip_rejected_first': False, 'untrusted_zip_sum_retained': False,
            'retry_succeeded': False, 'altered_inert_file_extracted': False}
PRIVATE_RECORDS = []
CONTROLS = ['verified-cold', 'verified-warm', 'fresh-consumer', 'zip-mismatch',
            'mod-mismatch', 'invalid-signature', 'authority-unavailable']


def export_ci_report(status):
    """Explicit safe fields only. Raw observations are sealed to the owner."""
    from ci_native_diagnostics import seal, write_new
    from oci_client_contract import read_owned_file
    if status not in ['passed', 'failed']:
        raise ValueError('Unknown checksum report status')
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('CI report requires an actual GitHub runner')
    candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        raise ValueError('CI report requires an exact source')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    if not re.fullmatch('[1-9][0-9]{0,19}', run_id) or os.environ.get('GITHUB_SHA') != candidate:
        raise ValueError('CI report requires matching actual run/source metadata')
    controls = PROGRESS['controls']
    if set(controls) - set(CONTROLS) or any(v not in ['passed', 'failed'] for v in controls.values()):
        raise ValueError('Unknown checksum control outcome')
    cache = ROOT / '.cache'
    cache.mkdir(exist_ok=True)
    report = {'schema': 1, 'candidate': candidate, 'run_id': run_id, 'status': status,
              'runner_os': platform.system(), 'runner_arch': platform.machine(),
              'go_version': PROGRESS.get('go_version'),
              'go_binary_sha256': PROGRESS.get('go_binary_sha256'),
              'fixture_sha256': hashlib.sha256(PUBLIC.read_bytes()).hexdigest(),
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'scripts/test_go_checksum_client.py', 'scripts/bounded_client.py', 'scripts/ci_native_diagnostics.py', 'scripts/oci_client_contract.py', 'internal/server/testdata/go-checksum-public.json', 'go.mod'], cwd=ROOT)),
              'controls': controls, 'required_controls': CONTROLS,
              'zip_rejected_first': PROGRESS['zip_rejected_first'],
              'untrusted_zip_sum_retained': PROGRESS['untrusted_zip_sum_retained'],
              'retry_succeeded': PROGRESS['retry_succeeded'],
              'altered_inert_file_extracted': PROGRESS['altered_inert_file_extracted'],
              'scope': 'Stock Go with owned TLS response stand-ins; no cratectl registry, PostgreSQL or package execution claim.'}
    if status == 'passed' and (set(controls) != set(CONTROLS) or set(controls.values()) != {'passed'}):
        raise ValueError('Incomplete controls cannot pass')
    if status == 'passed' and (report['source_dirty'] or not re.fullmatch(r'\d+\.\d+\.\d+', report['go_version'] or '') or not re.fullmatch('[0-9a-f]{64}', report['go_binary_sha256'] or '')):
        raise ValueError('Passing controls require clean source and pinned binary identity')
    if status == 'failed' and PRIVATE_RECORDS:
        if len(PRIVATE_RECORDS) > 8:
            raise ValueError('Checksum diagnostic inventory exceeds its bound')
        records = []
        for path in PRIVATE_RECORDS:
            if not re.fullmatch(r'go-checksum-client-[A-Za-z0-9_-]+\.(json|txt)', path.name):
                raise ValueError('Unexpected diagnostic name')
            raw = read_owned_file(ROOT / '.private', path, 256 << 10)
            records.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                            'body_base64': base64.b64encode(raw).decode('ascii')})
        payload = json.dumps({'candidate': candidate, 'records': records}, separators=(',', ':')).encode()
        if len(payload) > 1 << 20:
            raise ValueError('Checksum diagnostic payload exceeds its bound')
        certificate = ROOT / 'docs/qualification/ci-diagnostics-recipient.pem'
        ciphertext = seal(payload, certificate)
        target = cache / 'ci-go-checksum-client.cms'
        write_new(ROOT, target, ciphertext)
        report['encrypted_diagnostics'] = {'records': len(records), 'bytes': len(ciphertext),
                                            'sha256': hashlib.sha256(ciphertext).hexdigest(),
                                            'recipient_certificate_sha256': hashlib.sha256(certificate.read_bytes()).hexdigest(),
                                            'encryption': 'CMS AES-256-GCM with RSA-OAEP SHA-256 recipient'}
    write_new(ROOT, cache / 'ci-go-checksum-client-summary.json', (json.dumps(report, indent=2) + '\n').encode())


def main():
    os.chdir(ROOT)
    go = ROOT / '.cache/go/bin/go'
    if not go.is_file():
        executable = shutil.which('go')
        if not executable:
            raise SystemExit('Pinned native Go is required; no skipped checksum client control')
        go = Path(executable)
    pin = re.search(r'^go (\d+\.\d+\.\d+)$', (ROOT / 'go.mod').read_text(), re.M).group(1)
    observed = subprocess.check_output([str(go), 'version'], text=True).strip()
    if not observed.startswith('go version go' + pin + ' '):
        raise SystemExit('Pinned native Go is required')
    expected_platform = {'Darwin': 'darwin', 'Linux': 'linux'}[platform.system()]
    expected_arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    if not observed.endswith(' ' + expected_platform + '/' + expected_arch):
        raise SystemExit('Actual native Go architecture required')
    PROGRESS['go_version'] = pin
    with go.open('rb') as source:
        PROGRESS['go_binary_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
    fixture = json.loads(PUBLIC.read_bytes())
    module, version, key = (fixture[k] for k in ['module', 'version', 'verifier_key'])
    escaped = ''.join('!' + c.lower() if c.isupper() else c for c in module)
    prefix = escaped + '/@v/' + version
    mod = ('module ' + module + '\n\ngo 1.26.0\n').encode()
    payload = b'Owned inert stand-in; never execute package contents.\n'
    info = json.dumps({'Version': version, 'Time': '2026-01-02T03:04:05Z'}).encode()

    def archive(content):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in [('go.mod', mod), ('assets/inert.txt', content)]:
                entry = zipfile.ZipInfo(module + '@' + version + '/' + name, (2026, 1, 2, 3, 4, 6))
                entry.external_attr = 0o100644 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(entry, data)
        return output.getvalue()

    representations = {prefix + '.zip': archive(payload), prefix + '.mod': mod, prefix + '.info': info}
    responses = {path: base64.b64decode(body, validate=True) for path, body in fixture['responses'].items()}
    public_root = ROOT / '.private'
    public_root.mkdir(exist_ok=True, mode=0o700)
    if public_root.is_symlink() or public_root.stat().st_mode & 0o777 != 0o700:
        raise SystemExit('Owned .private must be an unlinked 0700 directory')
    old_mask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='cratectl-go-checksum-client-', dir=public_root) as folder:
            private = Path(folder)
            cert, secret = private / 'ca.crt', private / 'server.key'
            generated = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(secret), '-out', str(cert)], capture_output=True, timeout=30)
            if generated.returncode:
                raise SystemExit('Owned TLS client fixture certificate creation failed')
            counts = collections.Counter()
            mode = 'valid'

            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'

                def log_message(self, *_):
                    pass

                def do_GET(self):
                    parsed = urllib.parse.urlsplit(self.path)
                    path = urllib.parse.unquote(parsed.path)
                    counts[path] += 1
                    status, body = 404, b'Owned fixture has no such response\n'
                    if self.headers.get('Authorization') or parsed.query or mode == 'all-unavailable':
                        status, body = 503, b'Owned unavailable response\n'
                    elif path.startswith('/module/'):
                        path = path.removeprefix('/module/')
                        if path in representations:
                            status, body = 200, representations[path]
                            if mode == 'zip-mismatch' and path.endswith('.zip'):
                                body = archive(b'Changed inert bytes; never execute.\n')
                            if mode == 'mod-mismatch' and path.endswith('.mod'):
                                body += b'// changed but well-formed module metadata\n'
                    elif path.startswith('/checksum/'):
                        path = '/' + path.removeprefix('/checksum/')
                        if mode == 'authority-unavailable':
                            status, body = 503, b'Owned unavailable authority\n'
                        elif path in responses:
                            status, body = 200, responses[path]
                            if mode == 'invalid-signature' and path.startswith('/lookup/'):
                                # Corrupt a signature byte, leaving the original
                                # declared public key and all package bytes fixed.
                                head, signature = body.rsplit(b' ', 1)
                                signature = bytearray(signature)
                                signature[12] = ord('A') if signature[12] != ord('A') else ord('B')
                                body = head + b' ' + signature
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                        self.wfile.write(body)

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 38443), Handler)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, secret)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = 'https://localhost:38443'

            def environment(consumer, cache=None):
                env = {k: v for k, v in os.environ.items() if k not in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']}
                env.update(GOENV='off', GOWORK='off', GOFLAGS='', GOTOOLCHAIN='local', GOTELEMETRY='off', GOINSECURE='', GOPROXY=base + '/module', GOPRIVATE='', GONOPROXY='none', GONOSUMDB='', GOSUMDB=key + ' ' + base + '/checksum', GOVCS='*:off', GOAUTH='off', SSL_CERT_FILE=str(cert), GOMODCACHE=str(cache or consumer / 'module-cache'), GOPATH=str(consumer / 'gopath'), GOCACHE=str(consumer / 'build-cache'))
                return env

            def consumer(name):
                path = private / name
                path.mkdir()
                (path / 'go.mod').write_text('module go.cratectl.invalid/checksum-consumer\n\ngo 1.26.0\nrequire ' + module + ' ' + version + '\n')
                return path

            def download(path, env):
                code, output = run_owned_client([str(go), 'mod', 'download', '-json', 'all'], path, env, timeout=60, output_limit=2 << 20, capture_limit=2 << 20)
                (path / 'client-output.txt').write_text(output)
                try:
                    result = json.loads(output)
                except json.JSONDecodeError:
                    diagnosis = public_root / ('go-checksum-client-' + private.name + '-' + path.name + '-parse-failure.txt')
                    diagnosis.write_text(output[:65536])
                    PRIVATE_RECORDS.append(diagnosis)
                    if code != 0:
                        return code, {'Error': output[:65536], 'output_format':'non-json failure'}
                    raise AssertionError('Owned client returned non-JSON; bounded private diagnosis: ' + str(diagnosis)) from None
                return code, result

            checks = []
            try:
                good = consumer('verified-cold')
                env = environment(good)
                code, result = download(good, env)
                assert code == 0 and not result.get('Error'), result
                assert result['Sum'] == fixture['zip_h1'] and result['GoModSum'] == fixture['mod_h1']
                assert Path(result['Zip']).read_bytes() == representations[prefix + '.zip']
                assert Path(result['GoMod']).read_bytes() == mod
                assert (Path(result['Dir']) / 'assets/inert.txt').read_bytes() == payload
                assert counts['/checksum/lookup/' + escaped + '@' + version] > 0
                assert any(path.startswith('/checksum/tile/') for path in counts)
                assert any(p.read_bytes() == base64.b64decode(fixture['advanced_checkpoint']) for p in (good / 'gopath/pkg/sumdb').rglob('latest'))
                checks.append('cold stock Go verifies original signed lookup/tiles and exact module/mod h1 without checksum bypass')
                PROGRESS['controls']['verified-cold'] = 'passed'
                before = dict(counts)
                mode = 'all-unavailable'
                code, cached = download(good, env)
                assert code == 0 and not cached.get('Error') and dict(counts) == before
                assert cached['Sum'] == result['Sum'] and cached['GoModSum'] == result['GoModSum']
                checks.append('warm stock Go client cache uses retained verified sums without network contact')
                PROGRESS['controls']['verified-warm'] = 'passed'
                fresh = consumer('fresh-consumer-same-client-cache')
                code, cached = download(fresh, environment(fresh, Path(env['GOMODCACHE'])))
                assert code == 0 and not cached.get('Error') and dict(counts) == before
                expected = {module + ' ' + version + ' ' + fixture['zip_h1'], module + ' ' + version + '/go.mod ' + fixture['mod_h1']}
                assert set((fresh / 'go.sum').read_text().splitlines()) == expected
                checks.append('fresh consumer reuses the same verified client module cache offline with exact go.sum lines')
                PROGRESS['controls']['fresh-consumer'] = 'passed'
                control_failures = []
                for scenario in ['zip-mismatch', 'mod-mismatch', 'invalid-signature', 'authority-unavailable']:
                    mode = scenario
                    current = consumer(scenario)
                    code, failed = download(current, environment(current))
                    assert code != 0 and failed.get('Error'), (scenario, failed)
                    assert not failed.get('Dir') or not Path(failed['Dir']).exists(), scenario
                    if scenario.endswith('mismatch'):
                        assert 'checksum mismatch' in failed['Error'].lower(), (scenario, failed)
                    sums = set((current / 'go.sum').read_text().splitlines()) if (current / 'go.sum').exists() else set()
                    diagnosis = {'scenario':scenario,'exit_code':code,'result':failed,'go_sum':sorted(sums)}
                    if scenario == 'zip-mismatch':
                        PROGRESS['zip_rejected_first'] = code != 0
                        PROGRESS['untrusted_zip_sum_retained'] = not sums <= expected
                    if scenario == 'zip-mismatch' and not sums <= expected:
                        before_retry = dict(counts)
                        retry_code, retry_result = download(current, environment(current))
                        diagnosis['controlled_retry'] = {'exit_code':retry_code,'result':retry_result,'new_requests':dict(collections.Counter(counts)-collections.Counter(before_retry))}
                        PROGRESS['retry_succeeded'] = retry_code == 0
                        directory = Path(retry_result.get('Dir', current / 'absent'))
                        assert directory.resolve().is_relative_to(private.resolve()), 'Owned client cache path escaped fixture'
                        retained = directory / 'assets/inert.txt'
                        diagnosis['controlled_retry']['extracted_asset_exists'] = retained.is_file()
                        if retained.is_file():
                            body = retained.read_bytes()
                            diagnosis['controlled_retry']['extracted_asset_sha256'] = hashlib.sha256(body).hexdigest()
                            diagnosis['controlled_retry']['matches_altered_inert_payload'] = body == b'Changed inert bytes; never execute.\n'
                            PROGRESS['altered_inert_file_extracted'] = diagnosis['controlled_retry']['matches_altered_inert_payload']
                    diagnosis_path = public_root / ('go-checksum-client-' + private.name + '-' + scenario + '.json')
                    diagnosis_path.write_text(json.dumps(diagnosis,indent=2)+'\n')
                    PRIVATE_RECORDS.append(diagnosis_path)
                    # Stock Go can retain an independently verified go.mod sum
                    # while rejecting a changed ZIP. That is not ZIP admission.
                    try:
                        assert sums <= expected, (scenario, sums)
                        if scenario == 'zip-mismatch':
                            assert module + ' ' + version + ' ' + fixture['zip_h1'] not in sums
                        elif scenario == 'mod-mismatch':
                            assert module + ' ' + version + '/go.mod ' + fixture['mod_h1'] not in sums
                        else:
                            assert not sums, (scenario, sums)
                    except AssertionError:
                        PROGRESS['controls'][scenario] = 'failed'
                        control_failures.append(scenario)
                        continue
                    PROGRESS['controls'][scenario] = 'passed'
                    checks.append('cold stock Go refuses ' + scenario + ' without trusted sums or extracted module admission')
                assert not control_failures, 'Failed checksum client trust-state controls: ' + ', '.join(control_failures)
                print('PASS: ' + str(len(checks)) + ' native stock Go checksum-on TLS stand-in controls; no cratectl/PG proxy claim')
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)
                assert not worker.is_alive(), 'Owned checksum client fixture did not stop'
    finally:
        os.umask(old_mask)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ci-report', action='store_true', help='Write safe native metadata and owner-encrypted failure observations on GitHub only')
    arguments = parser.parse_args()
    outcome = 'failed'
    try:
        main()
        outcome = 'passed'
    finally:
        if arguments.ci_report:
            export_ci_report(outcome)
