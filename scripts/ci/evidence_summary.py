#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Export only reviewed CI evidence fields; never publish raw runner reports."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from native_client_diagnostics import CODES as NATIVE_CLIENT_DIAGNOSTIC_CODES
from gradle_evidence import safe_gradle_contract
from ivy_evidence import safe_ivy_contract


def summarize(root, environment):
    paths = subprocess.check_output(['git', 'ls-files', '--others', '--modified', '--exclude-standard', '-z', '--', 'evidence'], cwd=root).split(b'\0')
    if len(paths) > 201:
        raise SystemExit('Too many generated evidence files for a bounded CI summary')

    candidate = environment.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        raise SystemExit('CI evidence requires an exact candidate commit')
    native_os = {'Linux': 'linux', 'macOS': 'darwin', 'Windows': 'windows'}.get(environment.get('RUNNER_OS'))
    native_arch = {'X64': 'amd64', 'ARM64': 'arm64'}.get(environment.get('RUNNER_ARCH'))
    if native_os is None or native_arch is None:
        raise SystemExit('CI evidence requires a reviewed native runner platform')
    artifact_sources = {'.cache/ci-build/cratectld': candidate, '.cache/ci-build/cratectl': candidate, '.cache/bin/oras': None}
    manifest = root / 'docs/qualification/upgrade-baselines.json'
    if manifest.is_file():
        for baseline in json.loads(manifest.read_text())['baselines']:
            artifact_sources[baseline['binary']] = baseline['source']
    summary = {
        'candidate': candidate,
        'run_id': environment.get('GITHUB_RUN_ID', ''),
        'runner_os': environment.get('RUNNER_OS', ''),
        'runner_arch': environment.get('RUNNER_ARCH', ''),
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'records': [],
        'limits': [
            'Only counts, report hashes, reviewed binary digests and clean embedded source/platform identities are exported.',
            'Raw evidence, browser reports, private command logs and generated credentials remain on the disposable runner.',
            'This summary establishes only the named CI job stages, not release or product readiness.',
        ],
    }
    for raw_path in paths:
        if not raw_path:
            continue
        relative = Path(raw_path.decode())
        path = root / relative
        if path.suffix != '.json' or not path.is_file() or not path.resolve().is_relative_to(root / 'evidence'):
            continue
        data = path.read_bytes()
        if len(data) > 16 << 20:
            raise SystemExit('Generated evidence exceeds the CI summary byte budget')
        report = json.loads(data)
        if not isinstance(report, dict):
            continue
        record_candidate = report.get('candidate') or report.get('source_parent')
        if record_candidate and candidate and record_candidate != candidate:
            raise SystemExit('Generated evidence candidate does not match this CI run')
        status = report.get('status')
        if status not in ('passed', 'failed', 'running', 'manual-review-stopped'):
            status = 'passed' if report.get('passed') is True else 'failed' if report.get('passed') is False else 'unknown'
        entry = {
            'report': path.name,
            'raw_report_sha256': hashlib.sha256(data).hexdigest(),
            'status': status,
            'checks': len(report.get('checks', [])) if isinstance(report.get('checks'), list) else None,
            'cases': len(report.get('results', [])) if isinstance(report.get('results'), list) else None,
            'source_dirty': report.get('source_dirty') if isinstance(report.get('source_dirty'), bool) else None,
            'build_source_matches_candidate': report.get('build_source_matches_candidate') if isinstance(report.get('build_source_matches_candidate'), bool) else None,
        }
        if 'artifact_digests' in report:
            if not isinstance(report['artifact_digests'], dict) or len(report['artifact_digests']) > 16:
                raise SystemExit('Artifact identity evidence exceeds its inventory bound')
            entry['artifacts'] = []
            for name, digest in sorted(report['artifact_digests'].items()):
                if name not in artifact_sources or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    raise SystemExit('Artifact identity is outside the reviewed path/digest allowlist')
                artifact = {'path': name, 'sha256': digest}
                expected_source = artifact_sources[name]
                if expected_source:
                    identity = report.get('build_identity', {}).get(name, {})
                    settings = identity.get('settings', identity)
                    if settings.get('vcs.revision') != expected_source or settings.get('vcs.modified') != 'false' or settings.get('GOOS') not in ('linux', 'darwin', 'windows') or settings.get('GOARCH') not in ('amd64', 'arm64'):
                        raise SystemExit('Artifact embedded source identity is not the expected clean native build')
                    if settings['GOOS'] != native_os or settings['GOARCH'] != native_arch:
                        raise SystemExit('Artifact platform identity does not match the native runner')
                    artifact['build'] = {key: settings[key] for key in ('vcs.revision', 'vcs.modified', 'GOOS', 'GOARCH')}
                entry['artifacts'].append(artifact)
        if isinstance(report.get('browser_stats'), dict):
            entry['browser'] = {key: int(report['browser_stats'].get(key, 0)) for key in ('expected', 'unexpected', 'skipped', 'flaky')}
        if report.get('workflow') in ('all', 'repair', 'retention', 'nuget'):
            entry['workflow'] = report['workflow']
        if 'client_versions' in report:
            allowed = {'docker', 'docker_engine', 'buildx', 'podman', 'helm'}
            versions = report['client_versions']
            pattern = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}(?:\+g[0-9a-f]{7,40}|\+azure-[0-9]{1,3}|-desktop\.[0-9]{1,3})?'
            if not isinstance(versions, dict) or not set(versions) <= allowed or any(not isinstance(v, str) or not re.fullmatch(pattern, v) for v in versions.values()):
                raise SystemExit('Native client version evidence is outside the reviewed allowlist')
            if status == 'passed' and set(versions) != allowed:
                raise SystemExit('Passed native client evidence requires every client and engine version')
            entry['client_versions'] = dict(sorted(versions.items()))
            digests = report.get('client_binary_sha256', {})
            if not isinstance(digests, dict) or not set(digests) <= {'docker', 'podman', 'helm'} or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in digests.values()):
                raise SystemExit('Native client binary digest evidence is outside the reviewed allowlist')
            if status == 'passed' and set(digests) != {'docker', 'podman', 'helm'}:
                raise SystemExit('Passed native client evidence requires every reviewed client binary digest')
            entry['client_binary_sha256'] = dict(sorted(digests.items()))
            packages = report.get('client_packages', {})
            if not isinstance(packages, dict) or not set(packages) <= {'podman'}:
                raise SystemExit('Native client package evidence is outside the reviewed allowlist')
            entry['client_packages'] = {}
            for tool, package in packages.items():
                revision = r'(?:[0-9]{1,2}:)?4\.9\.3\+ds1-[0-9]{1,3}(?:ubuntu[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}|build[0-9]{1,3})'
                if not isinstance(package, dict) or not isinstance(package.get('version'), str) or not re.fullmatch(revision, package['version']) or package.get('architecture') != native_arch:
                    raise SystemExit('Native client package revision/platform is not reviewed')
                entry['client_packages'][tool] = {key: package[key] for key in ('version', 'architecture')}
            fixture_keys = {'application_v1', 'application_v2', 'dependency', 'fallback', 'other_tenant', 'foreign_platform', 'chart_dependency_1_0_0', 'chart_dependency_1_1_0', 'chart_application_1_0_0', 'chart_other_tenant_1_0_0'}
            fixtures = report.get('fixture_sha256', {})
            if not isinstance(fixtures, dict) or not set(fixtures) <= fixture_keys or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in fixtures.values()):
                raise SystemExit('Native client fixture identities are outside the reviewed allowlist')
            entry['fixture_sha256'] = dict(sorted(fixtures.items()))
            subjects = report.get('subjects', [])
            if not isinstance(subjects, list) or len(subjects) > 32:
                raise SystemExit('Native client subject inventory exceeds its bound')
            entry['subjects'] = []
            for subject in subjects:
                if not isinstance(subject, dict) or subject.get('repository') not in ('hosted', 'origin', 'proxy', 'fallback', 'host-group', 'proxy-group') or subject.get('image') not in ('payload', 'cratectl-application', 'cratectl-dependency') or subject.get('reference') not in ('v1', 'v2', 'foreign', 'multi', 'podman', '1.0.0', '1.1.0'):
                    raise SystemExit('Native client subject coordinate is not reviewed')
                if any(not isinstance(subject.get(key), str) or not re.fullmatch('sha256:[0-9a-f]{64}', subject[key]) for key in ('digest', 'native_manifest_digest')):
                    raise SystemExit('Native client subject digest is invalid')
                members = subject.get('members', [])
                if not isinstance(members, list) or not 1 < len(members) <= 16:
                    raise SystemExit('Native client graph inventory is invalid')
                for member in members:
                    if not isinstance(member, dict) or not isinstance(member.get('digest'), str) or not re.fullmatch('sha256:[0-9a-f]{64}', member['digest']) or type(member.get('size')) is not int or not 0 <= member['size'] <= 8 << 20:
                        raise SystemExit('Native client graph member identity is invalid')
                observation = {key: subject[key] for key in ('repository', 'image', 'reference', 'digest', 'native_manifest_digest')}
                observation['members'] = [{key: member[key] for key in ('digest', 'size')} for member in members]
                entry['subjects'].append(observation)
            if status == 'passed' and (set(packages) != {'podman'} or set(fixtures) != fixture_keys or not subjects):
                raise SystemExit('Passed native client evidence requires complete package/fixture/subject identities')
            phases = {'preflight', 'database', 'registry', 'authentication', 'image_publication', 'native_consumption', 'helm_dependencies', 'tenant_collision', 'policy_and_grants', 'retained_lifecycle', 'grant_revocation', 'restart', 'complete'}
            if report.get('phase') not in phases or status == 'passed' and report['phase'] != 'complete':
                raise SystemExit('Native client workflow phase is incomplete or unreviewed')
            entry['phase'] = report['phase']
            if 'command_failure_kind' in report:
                if report['command_failure_kind'] not in ('tls_profile', 'authorization', 'connection', 'client_flag', 'manifest_missing', 'blob_missing', 'platform_selection', 'unclassified'):
                    raise SystemExit('Native client error category is unreviewed')
                entry['command_failure_kind'] = report['command_failure_kind']
            if 'command_diagnostics' in report:
                codes = report['command_diagnostics']
                if not isinstance(codes, list) or len(codes) > len(NATIVE_CLIENT_DIAGNOSTIC_CODES) or any(not isinstance(code, str) or code not in NATIVE_CLIENT_DIAGNOSTIC_CODES for code in codes) or len(set(codes)) != len(codes):
                    raise SystemExit('Native client diagnostic codes are outside the reviewed allowlist')
                entry['command_diagnostics'] = sorted(codes)
        if 'nuget_sdk_version' in report:
            version = report['nuget_sdk_version']
            fixtures = report.get('nuget_fixture_sha256', {})
            binary = report.get('nuget_dotnet_sha256')
            allowed = {'dependency', 'application_1', 'application_2', 'other_application_1'}
            if not isinstance(version, str) or not re.fullmatch(r'10\.[0-9]{1,3}\.[0-9]{1,4}', version):
                raise SystemExit('NuGet client SDK version is outside the reviewed profile')
            if not isinstance(binary, str) or not re.fullmatch('[0-9a-f]{64}', binary):
                raise SystemExit('NuGet client binary digest is outside the reviewed profile')
            if not isinstance(fixtures, dict) or not set(fixtures) <= allowed or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in fixtures.values()):
                raise SystemExit('NuGet client fixture digests are outside the reviewed profile')
            if status == 'passed' and set(fixtures) != allowed:
                raise SystemExit('Passed NuGet client evidence requires all four owned fixtures')
            entry['nuget_sdk_version'] = version
            entry['nuget_dotnet_sha256'] = binary
            entry['nuget_fixture_sha256'] = dict(sorted(fixtures.items()))
            for name in ('nuget_protocol_probe_sha256', 'nuget_protocol_library_sha256'):
                if name in report:
                    if not isinstance(report[name], str) or not re.fullmatch('[0-9a-f]{64}', report[name]):
                        raise SystemExit('NuGet protocol identity must be a SHA256 digest')
                    entry[name] = report[name]
            if 'nuget_protocol_library_version' in report:
                value = report['nuget_protocol_library_version']
                if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}', value):
                    raise SystemExit('NuGet protocol library version is outside the reviewed profile')
                entry['nuget_protocol_library_version'] = value
            if 'nuget_metadata_contract' in report:
                value = report['nuget_metadata_contract']
                if not isinstance(value, dict) or set(value) != {'cases', 'fixture_sha256', 'observations_sha256', 'mismatch_indexes', 'phase'}:
                    raise SystemExit('NuGet HTTP metadata evidence fields are outside the reviewed profile')
                n = value['cases']
                if type(n) is not int or not 1 <= n <= 64 or value['phase'] not in ('published', 'restarted'):
                    raise SystemExit('NuGet HTTP metadata evidence exceeds its bounded corpus')
                if any(not isinstance(value[k], str) or not re.fullmatch('[0-9a-f]{64}', value[k]) for k in ('fixture_sha256', 'observations_sha256')):
                    raise SystemExit('NuGet HTTP metadata evidence must retain SHA256 identities')
                indexes = value['mismatch_indexes']
                if not isinstance(indexes, list) or any(type(i) is not int or i < 0 or i >= n for i in indexes) or len(set(indexes)) != len(indexes):
                    raise SystemExit('NuGet HTTP metadata mismatch indexes are outside the corpus')
                if status == 'passed' and (indexes or value['phase'] != 'restarted'):
                    raise SystemExit('Passed NuGet HTTP metadata evidence requires a complete restarted replay')
                entry['nuget_metadata_contract'] = value
                if 'nuget_metadata_diagnostics' in report:
                    diagnostics = report['nuget_metadata_diagnostics']
                    if not isinstance(diagnostics, list) or len(diagnostics) > 16:
                        raise SystemExit('NuGet HTTP diagnostic cases exceed their bound')
                    seen = set()
                    pattern = r'(?:groups(?:\[[0-9]{1,4}\])?(?:\.(?:framework|framework_name|packages(?:\[[0-9]{1,4}\])?(?:\.(?:id|min|max|min_metadata|max_metadata|include_min|include_max|floating|preference))?))?|license_acceptance)(?:\._(?:length|type))?'
                    for item in diagnostics:
                        if not isinstance(item, dict) or set(item) != {'index', 'failed', 'paths'} or type(item['index']) is not int or item['index'] not in indexes or item['index'] in seen or type(item['failed']) is not bool:
                            raise SystemExit('NuGet HTTP diagnostic identity is outside the failed corpus')
                        seen.add(item['index'])
                        if not isinstance(item['paths'], list) or len(item['paths']) > 64 or any(not isinstance(p, str) or len(p) > 128 or not re.fullmatch(pattern, p) for p in item['paths']):
                            raise SystemExit('NuGet HTTP diagnostic paths must use the fixed metadata schema')
                    entry['nuget_metadata_diagnostics'] = diagnostics
        if 'gradle_contract' in report:
            try:
                entry['gradle_contract'] = safe_gradle_contract(report['gradle_contract'], status)
            except ValueError as error:
                raise SystemExit(str(error)) from error
        if 'ivy_contract' in report:
            try:
                entry['ivy_contract'] = safe_ivy_contract(report['ivy_contract'], status)
            except ValueError as error:
                raise SystemExit(str(error)) from error
        for key in ('baseline_version', 'expected_schema'):
            if key in report:
                if type(report[key]) is not int or not 1 <= report[key] <= 1000:
                    raise SystemExit('Schema evidence must be a bounded positive integer')
                entry[key] = report[key]
        if 'baselines' in report:
            if not isinstance(report['baselines'], list) or len(report['baselines']) > 10:
                raise SystemExit('Historical build evidence exceeds its inventory bound')
            entry['baselines'] = []
            for baseline in report['baselines']:
                if baseline.get('schema') not in (None, *range(2, 11)) or not re.fullmatch('[0-9a-f]{40}', baseline.get('source', '')) or not re.fullmatch('[0-9a-f]{64}', baseline.get('binary_sha256', '')):
                    raise SystemExit('Historical build evidence has an invalid source or binary digest')
                entry['baselines'].append({key: baseline[key] for key in ('schema', 'source', 'binary_sha256')})
        summary['records'].append(entry)

    summary['records'].sort(key=lambda entry: entry['report'])
    return summary


def main():
    root = Path(__file__).resolve().parents[2]
    summary = summarize(root, os.environ)
    out = root / '.cache/ci-evidence-summary.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(f'Safe CI evidence summary: {len(summary["records"])} generated reports; {out.relative_to(root)}')
    if not summary['records']:
        raise SystemExit('No generated evidence records; refusing a successful empty summary')


if __name__ == '__main__':
    main()
