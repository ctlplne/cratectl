#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Seal only bounded owned portability command streams to the owner recipient."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_native_diagnostics import seal, write_new
from oci_client_contract import read_owned_file


def collect(root, candidate, run_id, role):
    if not re.fullmatch('[a-f0-9]{40}', candidate) or not re.fullmatch('[1-9][0-9]{0,19}', run_id) or role not in ('producer', 'consumer'):
        raise ValueError('Portability diagnostics require exact workflow/source/role identities')
    paths = subprocess.check_output(['git', 'ls-files', '--others', '--modified', '--exclude-standard', '-z', '--', 'evidence'], cwd=root).split(b'\0')
    if len(paths) > 201:
        raise ValueError('Portability diagnostic report inventory exceeds its bound')
    failures = []
    for raw in paths:
        if not raw:
            continue
        path = raw.decode('utf-8')
        match = re.fullmatch(r'evidence/\d{4}-\d{2}-\d{2}/go-(common-)?export-portability-([a-f0-9]{10})\.json', path)
        if not match:
            continue
        common, fixture_run = bool(match[1]), match[2]
        field = 'go_common_export_portability_contract' if common else 'go_export_portability_contract'
        profile = 'hosted-common-export-cross-runner-v1' if common else 'hosted-export-cross-runner-v1'
        report = json.loads(read_owned_file(root / 'evidence', root / path, 1 << 20))
        if not isinstance(report, dict) or not isinstance(report.get(field), dict):
            raise ValueError('Portability diagnostics require a reviewed report object')
        contract = report[field]
        if report.get('candidate') != candidate or contract.get('source_run_id') != run_id or contract.get('role') != role or contract.get('profile') != profile or report.get('run') != fixture_run:
            raise ValueError('Portability diagnostic context differs from the current job')
        if report.get('status') != 'failed':
            continue
        commands, error = report.get('commands'), report.get('failure', '')
        if len(failures) >= 2 or not isinstance(commands, list) or len(commands) > 32 or not isinstance(error, str) or len(error) > 8192:
            raise ValueError('Portability diagnostic command/error inventory exceeds its bound')
        selected = []
        for command in commands[-2:]:
            if not isinstance(command, dict) or command.get('exit') is not None and (type(command['exit']) is not int or not -255 <= command['exit'] <= 255):
                raise ValueError('Portability diagnostic command exit is invalid')
            log = command.get('private_log')
            prefix = '.private/go-' + ('common-' if common else '') + 'export-portability/' + fixture_run + '/'
            if not isinstance(log, str) or not re.fullmatch(re.escape(prefix) + r'command-[a-f0-9]{32}\.log', log):
                raise ValueError('Portability diagnostics cannot select private inputs or keys')
            item = {'exit': command.get('exit'), 'streams': []}
            for suffix in ['', '.stdout']:
                stream = root / (log + suffix)
                if suffix and not stream.exists():
                    continue  # Producer Go compilation uses combined capture.
                body = read_owned_file(root / '.private', stream, 8 << 20)
                item['streams'].append({'kind': 'stdout' if suffix else 'stderr_or_combined',
                                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                                        'head_b64': base64.b64encode(body[:512 << 10]).decode(),
                                        'tail_b64': base64.b64encode(body[-(512 << 10):]).decode(),
                                        'complete': len(body) <= 1 << 20})
            selected.append(item)
        failures.append({'run': fixture_run, 'role': role, 'profile': profile, 'error': error, 'commands': selected})
    if not failures:
        raise ValueError('No failed portability report is available; no empty diagnostic success')
    extended = any(f['profile'] == 'hosted-common-export-cross-runner-v1' for f in failures)
    return {'schema': 2 if extended else 1, 'candidate': candidate, 'run_id': run_id,
            'profile': 'hosted-export-command-diagnostics-v2' if extended else 'hosted-export-cross-runner-v1', 'failures': failures,
            'limits': ['Only the last two owned command streams are retained. Above1MiB, exact length/hash plus bounded head/tail replace the middle.',
                       'No package input, token/config, signing private key or SDK cache file is selected. No plaintext publication fallback.']}


def main():
    root = Path(__file__).resolve().parents[2]
    role = {'produce': 'producer', 'consume': 'consumer'}.get(os.environ.get('GITHUB_JOB'))
    arch = os.environ.get('RUNNER_ARCH')
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux' or role is None
            or arch != ('X64' if role == 'producer' else 'ARM64')):
        raise ValueError('Portability diagnostics require the declared actual native job')
    candidate, run_id = os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_RUN_ID', '')
    payload = collect(root, candidate, run_id, role)
    plaintext = json.dumps(payload, separators=(',', ':')).encode()
    certificate = root / 'docs/qualification/ci-diagnostics-recipient.pem'
    ciphertext = seal(plaintext, certificate)
    write_new(root / '.cache', root / '.cache/ci-go-export-diagnostics.cms', ciphertext)
    metadata = {'schema': 1, 'candidate': candidate, 'run_id': run_id, 'role': role, 'runner_arch': arch,
                'failed_reports': len(payload['failures']), 'ciphertext_bytes': len(ciphertext),
                'ciphertext_sha256': hashlib.sha256(ciphertext).hexdigest(),
                'recipient_certificate_sha256': hashlib.sha256(certificate.read_bytes()).hexdigest()}
    write_new(root / '.cache', root / '.cache/ci-go-export-diagnostics.json', (json.dumps(metadata, indent=2) + '\n').encode())


if __name__ == '__main__':
    main()
