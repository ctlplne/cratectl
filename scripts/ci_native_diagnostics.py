#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Seal bounded native-client failure logs to an owner-held CMS recipient.

OpenSSL supplies the standard CMS/AES-GCM/RSA-OAEP implementation. This tool
collects only command failures and registry logs, never auth/config/token files.
No plaintext fallback is permitted. The decryption key never visits CI.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from oci_client_contract import read_owned_file

MAX_LOG = 8 << 20
MAX_PAYLOAD = 24 << 20
MAX_CIPHERTEXT = MAX_PAYLOAD + (1 << 20)


def collect(root, candidate):
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        raise ValueError('diagnostics require an exact candidate')
    private_root = root / '.private'
    reports = sorted((private_root / 'oci-client-conformance').glob('*/progress.json'))
    if len(reports) > 4:
        raise ValueError('native diagnostic report inventory exceeds its bound')
    payload = {'schema': 1, 'candidate': candidate, 'failures': []}
    remaining = 16 << 20
    for path in reports:
        report = json.loads(read_owned_file(private_root, path, 1 << 20))
        if report.get('candidate') != candidate:
            raise ValueError('native diagnostic report source does not match')
        if report.get('status') != 'failed':
            continue
        run = path.parent.name
        if not re.fullmatch('[0-9a-f]{10}', run) or report.get('run') != run:
            raise ValueError('native diagnostic report identity is invalid')
        commands = report.get('commands', [])
        if not isinstance(commands, list) or len(commands) > 1024:
            raise ValueError('native diagnostic command inventory exceeds its bound')
        failure = {'run': run, 'phase': report.get('phase'), 'commands': []}
        error = report.get('failure', '')
        if not isinstance(error, str) or len(error) > 8192:
            raise ValueError('native diagnostic error exceeds its byte budget')
        failure['error'] = error
        selected = [command for command in commands if command.get('expected_success') is True and command.get('exit') != 0]
        observation_only = not selected
        if observation_only and isinstance(report.get('last_observation'), dict):
            selected = [report['last_observation']]
        for command in selected:
            # On a post-command assertion, preserve only the last observation
            # and mark its exit separately from an actual command failure.
            log = command.get('private_log', '')
            prefix = '.private/oci-client-conformance/' + run + '/'
            if not isinstance(log, str) or not re.fullmatch(re.escape(prefix) + r'command-[0-9a-f]{32}\.log', log):
                raise ValueError('native diagnostic log is not an owned command')
            if remaining <= 0:
                raise ValueError('native diagnostic log inventory exceeds its byte budget')
            raw = read_owned_file(private_root, root / log, min(MAX_LOG, remaining))
            remaining -= len(raw)
            failure['commands'].append({'label': command.get('label'), 'exit': command.get('exit'), 'observation_only': observation_only, 'sha256': hashlib.sha256(raw).hexdigest(), 'output_base64': base64.b64encode(raw).decode('ascii')})
            if len(failure['commands']) > 2:
                raise ValueError('native diagnostic failed-command count exceeds its bound')
        registry = path.parent / 'registry.log'
        if registry.exists() or registry.is_symlink():
            if remaining <= 0:
                raise ValueError('native diagnostic log inventory exceeds its byte budget')
            raw = read_owned_file(private_root, registry, min(MAX_LOG, remaining))
            remaining -= len(raw)
            failure['registry_log'] = {'sha256': hashlib.sha256(raw).hexdigest(), 'output_base64': base64.b64encode(raw).decode('ascii')}
        payload['failures'].append(failure)
    encoded = json.dumps(payload, separators=(',', ':')).encode()
    if len(encoded) > MAX_PAYLOAD:
        raise ValueError('native diagnostic payload exceeds its byte budget')
    return encoded, len(payload['failures'])


def collect_jvm(root, candidate):
    """Select only generated JVM failures and bounded command observations.

    These records are encrypted by main(), never exported as public summaries.
    Credential/config fields and successful command history are not collected.
    """
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        raise ValueError('JVM diagnostics require an exact candidate')
    generated = subprocess.check_output(['git','ls-files','--others','--modified','--exclude-standard','-z','--','evidence'],cwd=root).split(b'\0')
    if len(generated) > 201:
        raise ValueError('JVM generated report inventory exceeds its bound')
    failures = []
    remaining = 16 << 20
    for raw_path in generated:
        if not raw_path:
            continue
        path = raw_path.decode('utf-8')
        match = re.fullmatch(r'evidence/\d{4}-\d{2}-\d{2}/conformance-([0-9a-f]{10})\.json',path)
        if not match:
            continue
        report = json.loads(read_owned_file(root/'evidence',root/path,4 << 20))
        if not isinstance(report,dict):
            raise ValueError('JVM diagnostic report must be an object')
        if report.get('candidate') != candidate:
            raise ValueError('JVM diagnostic report source does not match')
        if report.get('status') != 'failed':
            continue
        clients = [client for client in ('gradle','ivy','sbt') if isinstance(report.get(client+'_contract'),dict)]
        if not clients:
            continue
        if len(clients) != 1 or report.get('run') != match[1] or len(failures) >= 4:
            raise ValueError('JVM diagnostic run/client inventory is invalid')
        client, run = clients[0], match[1]
        commands = report.get('commands')
        if not isinstance(commands,list) or len(commands)>1024 or any(not isinstance(c,dict) for c in commands):
            raise ValueError('JVM diagnostic command inventory exceeds its bound')
        selected = [c for c in commands if c.get('expected_failure') is not True and type(c.get('exit')) is int and c['exit'] != 0]
        observation_only = not selected
        if observation_only:
            selected = commands[-1:]
        if len(selected)>2:
            raise ValueError('JVM failed command inventory exceeds its bound')
        error = report.get('failure','')
        if not isinstance(error,str) or len(error)>8192:
            raise ValueError('JVM diagnostic error exceeds its bound')
        failure = {'run':run,'client':client,'error':error,'commands':[]}
        for command in selected:
            output = command.get('output',''); code = command.get('exit')
            if not isinstance(output,str) or len(output)>12000 or type(code) is not int or not -255<=code<=255:
                raise ValueError('JVM diagnostic observation exceeds its bound')
            encoded = output.encode('utf-8')
            remaining -= len(encoded)
            if remaining<0:
                raise ValueError('JVM diagnostic output inventory exceeds its bound')
            failure['commands'].append({'exit':code,'observation_only':observation_only,
                                        'sha256':hashlib.sha256(encoded).hexdigest(),'output_base64':base64.b64encode(encoded).decode('ascii')})
        registry = root/'.private/conformance'/run/'server.log'
        if registry.exists() or registry.is_symlink():
            if remaining<=0:
                raise ValueError('JVM diagnostic registry inventory exceeds its bound')
            raw = read_owned_file(root/'.private',registry,min(MAX_LOG,remaining))
            remaining -= len(raw)
            failure['registry_log'] = {'sha256':hashlib.sha256(raw).hexdigest(),'output_base64':base64.b64encode(raw).decode('ascii')}
        failures.append(failure)
    return failures


def seal(payload, certificate, openssl='openssl'):
    if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
        raise ValueError('native diagnostic plaintext exceeds its byte budget')
    completed = subprocess.run([openssl, 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER', '-recip', str(certificate), '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256'], input=payload, capture_output=True, timeout=30)
    if completed.returncode or not completed.stdout or len(completed.stdout) > MAX_CIPHERTEXT:
        raise ValueError('native diagnostic encryption failed; plaintext remains private')
    return completed.stdout


def unseal(ciphertext, key, certificate, openssl='openssl'):
    if not isinstance(ciphertext, bytes) or not 0 < len(ciphertext) <= MAX_CIPHERTEXT:
        raise ValueError('native diagnostic ciphertext exceeds its byte budget')
    completed = subprocess.run([openssl, 'cms', '-decrypt', '-binary', '-inform', 'DER', '-recip', str(certificate), '-inkey', str(key)], input=ciphertext, capture_output=True, timeout=30)
    # CMS implementations can stream bytes before the final GCM tag check.
    # Never expose those bytes unless decryption and authentication succeeded.
    if completed.returncode or len(completed.stdout) > MAX_PAYLOAD:
        raise ValueError('native diagnostic authentication/decryption failed')
    return completed.stdout


def write_new(root, path, body):
    root, path = root.absolute(), path.absolute()
    parts = path.relative_to(root).parts
    if not parts or any(part in ('.', '..') for part in parts):
        raise ValueError('native diagnostic output must stay in its owned root')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=directory)
            except FileExistsError:
                pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--decrypt', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.umask(0o077)
    certificate = root / 'docs/qualification/ci-diagnostics-recipient.pem'
    if args.decrypt:
        if not args.key or not args.output or not args.output.absolute().is_relative_to(root / '.private') or '..' in args.output.parts:
            raise ValueError('decryption requires an explicit key and a new private output')
        ciphertext = read_owned_file(root / '.cache', args.decrypt, MAX_CIPHERTEXT)
        plaintext = unseal(ciphertext, args.key, certificate)
        write_new(root / '.private', args.output, plaintext)
        print('PASS: authenticated diagnostic payload written to private local state')
        return
    candidate = os.environ.get('GITHUB_SHA', '')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if candidate != actual:
        raise ValueError('native diagnostics require the actual CI source')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    arch = os.environ.get('RUNNER_ARCH', '')
    if not re.fullmatch('[0-9]{1,20}', run_id) or os.environ.get('RUNNER_OS') != 'Linux' or arch not in ('X64', 'ARM64'):
        raise ValueError('native diagnostics require a reviewed GitHub Linux run identity')
    payload, count = collect(root, candidate)
    decoded = json.loads(payload)
    jvm = collect_jvm(root, candidate)
    decoded['failures'].extend(jvm)
    count += len(jvm)
    decoded.update(run_id=run_id, runner_os='Linux', runner_arch=arch)
    payload = json.dumps(decoded, separators=(',', ':')).encode()
    if len(payload) > MAX_PAYLOAD:
        raise ValueError('native diagnostic payload exceeds its byte budget')
    version = subprocess.check_output(['openssl', 'version'], text=True, timeout=10)
    version = re.match(r'OpenSSL ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})\b', version)
    if not version:
        raise ValueError('native diagnostics require an observed OpenSSL version')
    metadata = {'candidate': candidate, 'run_id': run_id, 'runner_os': 'Linux', 'runner_arch': arch, 'openssl_version': version[1], 'status': 'encrypted' if count else 'no_native_failure_record', 'records': count}
    if count:
        ciphertext = seal(payload, certificate)
        write_new(root / '.cache', root / '.cache/ci-native-diagnostics.cms', ciphertext)
        metadata.update(ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(), recipient_certificate_sha256=hashlib.sha256(certificate.read_bytes()).hexdigest(), encryption='CMS AES-256-GCM with RSA-OAEP SHA-256 recipient')
    write_new(root / '.cache', root / '.cache/ci-native-diagnostics.json', json.dumps(metadata, indent=2).encode() + b'\n')
    print('Native diagnostic records: ' + str(count) + '; only ciphertext and fixed metadata may be uploaded')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Native diagnostic processing failed; no plaintext fallback') from None
