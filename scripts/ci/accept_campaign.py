#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Read-only exact-source campaign acceptance, manually dispatched on main."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys

from campaign_contract import COMPATIBLE_FILES, WORKFLOWS, jobs as job_contracts
from campaign_reports import validate_custom, validate_summary
from campaign_transport import (EvidenceError, GitHubEvidenceClient, LOG_BYTES,
                                REPOSITORY, artifact_json, require, strict_json)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from bounded_client import run_owned_client

SHA = re.compile('[a-f0-9]{40}')


def git_bytes(arguments):
    output = io.BytesIO()
    code, _ = run_owned_client(['git', '--no-replace-objects', '-c', 'core.pager=cat', *arguments],
                               ROOT, {'PATH': os.environ['PATH'], 'GIT_CONFIG_NOSYSTEM': '1',
                                      'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'},
                               timeout=30, output_limit=8 << 20, capture_limit=1, output_sink=output)
    require(code == 0, 'candidate_git_unavailable')
    return output.getvalue()


class Source:
    def __init__(self, candidate):
        require(isinstance(candidate, str) and SHA.fullmatch(candidate), 'candidate_identity')
        self.candidate = candidate
        self.verifier = git_bytes(['rev-parse', 'HEAD']).decode().strip()
        require(SHA.fullmatch(self.verifier), 'verifier_identity')
        git_bytes(['merge-base', '--is-ancestor', candidate, self.verifier])
        require(not git_bytes(['status', '--porcelain']), 'verifier_dirty')
        owners = git_bytes(['log', '--format=%an <%ae>|%cn <%ce>', self.verifier]).decode().splitlines()
        expected = 'imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>'
        require(owners and all(line == expected + '|' + expected for line in owners), 'commit_owner_identity')
        self.paths = set(git_bytes(['ls-tree', '-r', '--name-only', '-z', candidate]).decode().strip('\0').split('\0'))
        require(0 < len(self.paths) <= 20000, 'candidate_file_inventory')
        self.cache = {}
        self.remaining = 64 << 20
        self.compatibility = []
        for name in COMPATIBLE_FILES:
            current = (ROOT / name).read_bytes()
            require(self(name) == current, 'unsupported_source_contract_revision')
            self.compatibility.append({'path': name, 'sha256': hashlib.sha256(current).hexdigest()})
        self.baselines = strict_json(self('docs/qualification/upgrade-baselines.json'))['baselines']
        require(isinstance(self.baselines, list) and len(self.baselines) == 16, 'unsupported_baseline_inventory')
        pg, go, fuzz = [], [], []
        for name in sorted(self.paths):
            if not name.endswith('_test.go') or not name.startswith(('internal/', 'cmd/')):
                continue
            body = self(name).decode()
            fuzz.extend((name, n) for n in re.findall(r'^func\s+(Fuzz\w+)\s*\(', body, re.M))
            if re.fullmatch(r'internal/(store|server|conformance)/.*_integration_test.go', name):
                require(not re.search(r'\.Skip(?:f|Now)?\s*\(', body), 'source_integration_skip')
                functions = re.findall(r'^func\s+(Test\w+)\s*\(', body, re.M)
                pg.extend((name, n) for n in functions)
                if re.fullmatch(r'internal/(store|server)/go_module.*_integration_test.go', name):
                    go.extend((name, n) for n in functions if n.startswith('TestGoModule'))
        require(0 < len(pg) <= 10000 and 0 < len(go) <= len(pg) and 0 < len(fuzz) <= 100, 'source_test_inventory')
        require(b'.Skip' not in self('internal/testdb/database.go'), 'source_database_skip')
        self.inventory = {'integration_functions': len(pg), 'named_go_functions': len(go), 'fuzz_targets': len(fuzz),
                          'inventory_sha256': hashlib.sha256(json.dumps([pg, go, fuzz], separators=(',', ':')).encode()).hexdigest()}

    def __call__(self, name):
        require(name in self.paths, 'candidate_source_file_missing')
        if name not in self.cache:
            raw = git_bytes(['show', self.candidate + ':' + name])
            require(len(raw) <= 2 << 20, 'candidate_source_file_limit')
            self.remaining -= len(raw)
            require(self.remaining >= 0, 'candidate_source_total_limit')
            self.cache[name] = raw
        return self.cache[name]


def discover(client, candidate):
    result = {}
    for run in client.listing('runs?head_sha=' + candidate + '&per_page=100', 'workflow_runs'):
        require(isinstance(run, dict) and run.get('head_sha') == candidate, 'api_candidate_inventory')
        if run.get('event') not in ('push', 'workflow_dispatch', 'schedule') or run.get('head_branch') != 'main':
            continue
        require(run.get('repository', {}).get('full_name') == REPOSITORY
                and run.get('head_repository', {}).get('full_name') == REPOSITORY, 'run_repository_identity')
        path = run.get('path', '').split('@')[0]
        if path == '.github/workflows/qualification-acceptance.yml':
            continue  # The verifier is not another native test profile.
        require(path.startswith('.github/workflows/') and path.removeprefix('.github/workflows/') in WORKFLOWS, 'unsupported_workflow')
        identifier = run.get('id')
        require(type(identifier) is int and 0 < identifier < 10 ** 18 and identifier not in result, 'run_inventory')
        result[identifier] = (WORKFLOWS[path.removeprefix('.github/workflows/')], run)
    return result


def artifact_metadata(artifact, candidate, run_id, maximum=2 << 20):
    require(isinstance(artifact, dict) and artifact.get('expired') is False
            and type(artifact.get('id')) is int and 0 < artifact['id'] < 10 ** 18
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= maximum
            and artifact.get('workflow_run', {}).get('id') == run_id
            and artifact['workflow_run'].get('head_sha') == candidate, 'artifact_identity')
    digest = artifact.get('digest')
    require(isinstance(digest, str) and re.fullmatch('sha256:[a-f0-9]{64}', digest), 'artifact_digest_missing')
    return {'artifact_id': artifact['id'], 'reported_archive_sha256': digest.removeprefix('sha256:'),
            'archive_bytes': artifact['size_in_bytes']}


def safe_artifact(client, artifact, candidate, run_id, member):
    artifact_metadata(artifact, candidate, run_id)
    raw = client.get('artifacts/' + str(artifact['id']) + '/zip', redirect=True)
    value, digest = artifact_json(raw, artifact.get('digest'), member)
    return value, {'artifact_id': artifact['id'], 'archive_sha256': hashlib.sha256(raw).hexdigest(), 'member_sha256': digest}


def check_log(raw, spec, source):
    text = raw.decode('utf-8', errors='replace')
    require('--- FAIL:' not in text and '--- SKIP:' not in text, 'native_test_failure_or_skip')
    kind = spec['kind']
    if kind in ('native', 'go'):
        pattern = r'\bok\s+ctlplne.dev/cratectl/internal/(?:server|store' + ('|conformance' if kind == 'native' else '') + r')\s'
        require(len(re.findall(pattern, text)) == (6 if kind == 'native' else 4), 'native_package_success_inventory')
    if kind == 'fuzz':
        count = source.inventory['fuzz_targets']
        system = 'Darwin' if spec['platform'][1] == 'macOS' else 'Linux'
        machine = {'amd64': 'x86_64', 'arm64': 'aarch64', 'darwin-arm64': 'arm64'}[spec['arch']]
        require('PASS: ' + str(count) + ' bounded native Go fuzz targets' in text
                and 'Native ' + system + ' ' + machine + ': ' + str(count) + ' Go fuzz targets, 5 seconds each' in text, 'native_fuzz_inventory')
    needs_ports = kind in ('native', 'go', 'gradle', 'ivy', 'sbt', 'oci', 'upgrades', 'producer') or kind.startswith('browser-')
    if needs_ports and 'scripts/ci/prepare_owned_ports.py' in source.paths:
        observations = []
        for line in text.splitlines():
            if '"profile": "cratectl-owned-ci-ports-v1"' in line:
                require(len(line) < 16384 and '{' in line, 'kernel_observation_limit')
                observations.append(strict_json(line[line.index('{'):].encode()))
        require(len(observations) == 1, 'kernel_observation_inventory')
        proof = observations[0]
        require(proof.get('source_sha256') == hashlib.sha256(source('scripts/ci/prepare_owned_ports.py')).hexdigest()
                and proof.get('owned_ports') == [35432, 38443]
                and proof.get('machine') == ('x86_64' if spec['arch'] == 'amd64' else 'aarch64')
                and proof.get('kernel_controls') == [
                    {'mode': 'unreserved', 'automatic_uses_owned_port': True, 'explicit_bind_succeeds': False},
                    {'mode': 'reserved', 'automatic_uses_owned_port': False, 'explicit_bind_succeeds': True}], 'kernel_observation_identity')


def accept(client, source, expected_ids):
    require(isinstance(expected_ids, list) and 0 < len(expected_ids) <= 32
            and all(type(n) is int and 0 < n < 10 ** 18 for n in expected_ids)
            and len(set(expected_ids)) == len(expected_ids), 'expected_run_inventory')
    runs = discover(client, source.candidate)
    require(set(runs) == set(expected_ids) and any(f == 'main' for f, _ in runs.values()), 'observed_run_inventory_differs')
    accepted, unselected, portable, portable_runners, transfers = [], [], {}, {}, []
    total_jobs = 0
    for run_id in sorted(runs):
        family, run = runs[run_id]
        require(type(run.get('run_attempt')) is int and run['run_attempt'] == 1 and run.get('status') == 'completed'
                and run.get('conclusion') == 'success', 'run_not_accepted')
        jobs = client.listing('runs/' + str(run_id) + '/jobs?per_page=100', 'jobs')
        artifacts = client.listing('runs/' + str(run_id) + '/artifacts?per_page=100', 'artifacts')
        total_jobs += len(jobs)
        require(total_jobs <= 100 and jobs, 'campaign_job_limit')
        names = [j.get('name') for j in jobs if isinstance(j, dict)]
        require(len(names) == len(jobs) and len(set(names)) == len(names), 'job_inventory')
        require(all(type(j.get('id')) is int and 0 < j['id'] < 10 ** 18 and j.get('run_id') == run_id
                    and j.get('head_sha') == source.candidate and j.get('head_branch') == 'main' for j in jobs), 'job_source_inventory')
        by_artifact = {a.get('name'): a for a in artifacts if isinstance(a, dict)}
        require(len(by_artifact) == len(artifacts), 'artifact_inventory')
        if family == 'portable':
            capsule = by_artifact.get('cratectl-owned-go-export-fixture')
            # Native producer/consumer jobs independently verify all capsule
            # members. Preserve its API identity without downloading/executing it.
            transfers.append({'run_id': run_id, **artifact_metadata(capsule, source.candidate, run_id, 26 << 20)})
        specs = job_contracts(family)
        runtime = True
        used = set()
        if family == 'main':
            require('ci-selection' in by_artifact, 'selection_artifact_missing')
            selection, _ = safe_artifact(client, by_artifact['ci-selection'], source.candidate, run_id, 'ci-selection.json')
            require(isinstance(selection, dict) and type(selection.get('schema')) is int and selection['schema'] == 1
                    and selection.get('candidate') == source.candidate and type(selection.get('runtime')) is bool, 'selection_identity')
            runtime = selection['runtime']
            used.add('ci-selection')
            if not runtime:
                specs = {n: v for n, v in specs.items() if v['kind'] in ('selection', 'security')}
                skipped = [j for j in jobs if j['name'] not in specs]
                require(all(j.get('status') == 'completed' and j.get('conclusion') == 'skipped' for j in skipped), 'documentation_runtime_not_skipped')
                unselected.append({'run_id': run_id, 'scope': 'runtime', 'jobs': len(skipped)})
                jobs = [j for j in jobs if j['name'] in specs]
                names = [j['name'] for j in jobs]
        if family == 'browser' and run['event'] == 'workflow_dispatch':
            require(len(names) == 1 and set(names) <= set(specs), 'focused_browser_selection')
            specs = {name: specs[name] for name in names}
        require(set(names) == set(specs), 'job_inventory_differs')
        for job in jobs:
            spec = specs[job['name']]
            require(job.get('run_id') == run_id and job.get('head_sha') == source.candidate
                    and type(job.get('id')) is int and 0 < job['id'] < 10 ** 18
                    and job.get('head_branch') == 'main' and job.get('status') == 'completed'
                    and job.get('conclusion') == 'success' and job.get('labels') == [spec['platform'][0]], 'job_native_identity')
            steps = job.get('steps')
            require(isinstance(steps, list) and len(steps) <= 100
                    and not any(s.get('conclusion') in ('failure', 'cancelled', 'timed_out') for s in steps), 'job_step_failure')
            for name in spec['required']:
                matches = [s for s in steps if s.get('name') == name]
                require(len(matches) == 1 and matches[0].get('status') == 'completed' and matches[0].get('conclusion') == 'success', 'required_step_not_passed')
            if spec['kind'] == 'native' and spec['arch'] == 'arm64':
                browser = [s for s in steps if s.get('name') == 'Chromium console workflows and accessibility']
                require(len(browser) == 1 and browser[0].get('status') == 'completed' and browser[0].get('conclusion') == 'skipped', 'arm_browser_selection')
            raw_log = client.get('jobs/' + str(job['id']) + '/logs', maximum=LOG_BYTES, redirect=True)
            check_log(raw_log, spec, source)
            item = {'family': family, 'run_id': run_id, 'job_id': job['id'], 'name': job['name'],
                    'platform': list(spec['platform']), 'log_bytes': len(raw_log), 'log_sha256': hashlib.sha256(raw_log).hexdigest()}
            if spec['kind'] == 'native' and spec['arch'] == 'arm64':
                item['unselected'] = ['chromium']
            artifact_name = spec['artifact']
            if artifact_name and spec['kind'] != 'selection':
                require(artifact_name in by_artifact, 'required_artifact_missing')
                used.add(artifact_name)
                member = 'nuget-version-summary.json' if spec['kind'] == 'library' else 'ci-go-checksum-client-summary.json' if spec['kind'] == 'strict' else 'ci-evidence-summary.json'
                report, reference = safe_artifact(client, by_artifact[artifact_name], source.candidate, run_id, member)
                if spec['kind'] in ('library', 'strict'):
                    counts = validate_custom(report, source.candidate, run_id, spec, source)
                else:
                    counts, contract = validate_summary(report, source.candidate, run_id, spec, source.baselines, source)
                    if contract is not None:
                        require(isinstance(job.get('runner_name'), str) and type(job.get('runner_id')) is int and job['runner_id'] > 0, 'portable_runner_metadata')
                        key = 'source_runner_sha256' if contract['role'] == 'producer' else 'destination_runner_sha256'
                        require(contract[key] == hashlib.sha256(job['runner_name'].encode()).hexdigest(), 'portable_runner_identity')
                        portable.setdefault(run_id, {})[contract['role']] = contract
                        portable_runners.setdefault(run_id, {})[contract['role']] = job['runner_id']
                item.update(artifact=reference, report_counts=counts)
            accepted.append(item)
        require({name for name in by_artifact if isinstance(name, str) and (name.startswith('ci-summary-') or name == 'ci-selection')} == used, 'unexpected_safe_artifact')
    for run_id, roles in portable.items():
        require(set(roles) == {'producer', 'consumer'}, 'portable_pair_missing')
        a, b = roles['producer'], roles['consumer']
        for key in ('profile', 'fixture_sha256', 'public_key_sha256', 'source_runner_sha256', 'source_run_id', 'source_arch', 'fixture_source_sha256', 'script_sha256', 'files_sha256'):
            require(a[key] == b[key], 'portable_pair_identity')
        require(b['network_isolated'] is True and b['source_runner_sha256'] != b['destination_runner_sha256'], 'portable_pair_isolation')
        require(portable_runners[run_id]['producer'] != portable_runners[run_id]['consumer'], 'portable_pair_isolation')
    require(discover(client, source.candidate) == runs, 'campaign_snapshot_changed')
    families = {f for f, _ in runs.values()}
    return {'schema': 1, 'profile': 'cratectl-ci-campaign-v1', 'status': 'passed',
            'candidate': source.candidate, 'verifier': source.verifier, 'run_ids': sorted(runs),
            'jobs': accepted, 'unselected_runtime': unselected,
            'portable_transfer_artifacts': transfers,
            'unselected_workflows': sorted(set(WORKFLOWS.values()) - families),
            'source_inventory': source.inventory, 'compatible_source_contracts': source.compatibility,
            'goal_complete': False, 'broad_readiness': False,
            'limits': ['Only the exact observed run inventory and required job/report contracts are accepted. Newly dispatched runs require another verdict.',
                       'Unselected and skipped lanes are not passes; original failures and independently reviewed native records retain their scope.',
                       'This is not full450capabilities/41families/laterGOAL readiness, security, packaging or release approval.']}


def main():
    os.umask(0o077)
    candidate = os.environ.get('CRATECTL_CAMPAIGN_CANDIDATE', '')
    failure = {'schema': 1, 'profile': 'cratectl-ci-campaign-v1', 'status': 'not_accepted',
               'candidate': candidate if SHA.fullmatch(candidate) else None, 'goal_complete': False, 'broad_readiness': False}
    result = dict(failure)
    try:
        require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REF') == 'refs/heads/main'
                and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == 'X64'
                and os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'dispatch_context')
        identifiers = os.environ.get('CRATECTL_CAMPAIGN_RUN_IDS', '')
        require(len(identifiers) <= 4096, 'expected_run_inventory')
        source = Source(candidate)
        require(source.verifier == os.environ.get('GITHUB_SHA'), 'verifier_dispatch_identity')
        result = accept(GitHubEvidenceClient(os.environ.get('GH_TOKEN')), source, strict_json(identifiers.encode()))
        run_id = os.environ.get('GITHUB_RUN_ID', '')
        require(re.fullmatch('[1-9][0-9]{0,19}', run_id), 'verifier_run_identity')
        result['verifier_run_id'] = run_id
    except Exception as exc:
        code = str(exc) if isinstance(exc, EvidenceError) else 'campaign_verification_failed'
        result = {**failure, 'category': code if re.fullmatch('[a-z_]{1,80}', code) else 'campaign_verification_failed'}
    destination = ROOT / '.cache/ci-campaign-verdict.json'
    destination.parent.mkdir(exist_ok=True)
    pending = destination.with_suffix('.pending')
    with pending.open('xb') as output:
        output.write((json.dumps(result, indent=2) + '\n').encode())
        output.flush()
        os.fsync(output.fileno())
    os.link(pending, destination)  # Existing receipts are preserved.
    pending.unlink()
    print('Campaign verdict: ' + result['status'])
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
