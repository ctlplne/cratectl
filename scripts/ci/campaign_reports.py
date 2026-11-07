#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check existing safe reports; return only constructed counts and hashes."""
import ast
import hashlib
import json
import re

from campaign_transport import require
from maven_evidence import safe_maven_cache_contract
from gradle_evidence import safe_gradle_contract
from ivy_evidence import safe_ivy_contract
from sbt_evidence import safe_sbt_contract
from go_module_evidence import safe_go_module_contract
from journal_evidence import safe_journal_checkpoint_contract
from go_export_portability_evidence import safe_go_export_portability_contract
from go_common_export_portability_evidence import safe_go_common_export_portability_contract

CONTRACTS = {'maven_cache_contract': safe_maven_cache_contract, 'gradle_contract': safe_gradle_contract,
             'ivy_contract': safe_ivy_contract, 'sbt_contract': safe_sbt_contract,
             'go_module_contract': safe_go_module_contract, 'journal_checkpoint_contract': safe_journal_checkpoint_contract,
             'go_export_portability_contract': safe_go_export_portability_contract,
             'go_common_export_portability_contract': safe_go_common_export_portability_contract}
NATIVE_COUNTS = {'conformance': 683, 'hold-matters': 31, 'installation': 30,
                 'inventory': 67, 'jobs': 71, 'leases': 63, 'native-lifecycle': 335, 'sweeps': 80}
HASH = re.compile('[a-f0-9]{64}')
BASE_FIELDS = {'report', 'raw_report_sha256', 'status', 'checks', 'cases', 'source_dirty', 'build_source_matches_candidate'}
EXTRA_FIELDS = {'artifacts', 'browser', 'workflow', 'client_versions', 'client_binary_sha256', 'client_packages',
                'fixture_sha256', 'phase', 'subjects', 'baseline_version', 'expected_schema', 'baselines',
                'nuget_sdk_version', 'nuget_dotnet_sha256', 'nuget_fixture_sha256', 'nuget_protocol_probe_sha256',
                'nuget_protocol_library_sha256', 'nuget_protocol_library_version', 'nuget_metadata_contract',
                'nuget_metadata_diagnostics', 'command_failure_kind', 'command_diagnostics', *CONTRACTS}


def hash_value(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def identity(report, candidate, run_id, spec):
    require(isinstance(report, dict) and report.get('candidate') == candidate
            and str(report.get('run_id')) == str(run_id), 'report_source_identity')
    _, os_name, arch = spec['platform']
    observed_os = {'Darwin': 'macOS'}.get(report.get('runner_os'), report.get('runner_os'))
    observed_arch = {'amd64': 'X64', 'arm64': 'ARM64', 'x86_64': 'X64', 'aarch64': 'ARM64'}.get(report.get('runner_arch'), report.get('runner_arch'))
    require(observed_os == os_name and observed_arch == arch, 'report_native_identity')


def go_deterministic_bindings(raw):
    """Read literal fixture inputs with AST; never execute the candidate script."""
    constants, fixtures = {}, None
    for node in ast.parse(raw).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name in ('INSTANT', 'MODULE', 'DEPENDENCY'):
            require(isinstance(node.value, ast.Constant) and isinstance(node.value.value, str), 'go_literal_fixture')
            constants[name] = node.value.value
        elif name == 'fixtures':
            fixtures = node.value
    require(set(constants) == {'INSTANT', 'MODULE', 'DEPENDENCY'} and isinstance(fixtures, ast.Dict)
            and len(fixtures.keys) == 8, 'go_literal_fixture')

    def literal(node):
        if isinstance(node, ast.Name):
            require(node.id in constants, 'go_literal_fixture')
            return constants[node.id]
        require(isinstance(node, ast.Constant) and isinstance(node.value, str), 'go_literal_fixture')
        return node.value

    result = {}
    for key, value in zip(fixtures.keys, fixtures.values):
        label = literal(key)
        require(isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'fixture'
                and not value.keywords and len(value.args) in (3, 4), 'go_literal_fixture')
        values = [literal(n) for n in value.args]
        module, version = values[:2]
        dependency = values[3] if len(values) == 4 else None
        mod = ('module ' + module + '\n\ngo 1.26.0\n' + ('require ' + dependency + ' v1.0.0\n' if dependency else '')).encode()
        info = json.dumps({'Version': version, 'Time': constants['INSTANT']}, separators=(',', ':')).encode()
        for kind, data in [('mod', mod), ('info', info)]:
            result[label + '_' + kind] = hashlib.sha256(data).hexdigest()
    require(len(result) == 16, 'go_literal_fixture')
    return result


def validate_custom(report, candidate, run_id, spec, source):
    identity(report, candidate, run_id, spec)
    require(report.get('status') == 'passed' and report.get('source_dirty') is False, 'custom_report_incomplete')
    if spec['kind'] == 'library':
        require(report.get('phase') == 'complete' and isinstance(report.get('checks'), list)
                and len(report['checks']) == 37 and report.get('sdk_version') == '10.0.403'
                and report.get('nuget_library_version') == '7.9.0.0'
                and report.get('go_build_identity') == {'vcs.modified': 'false', 'vcs.revision': candidate}, 'library_profile')
        mismatch_fields = {'mismatch_indexes'} | {prefix + suffix for prefix in
                          ['archive', 'comparison', 'dependency', 'id', 'nuspec', 'ordinal', 'property', 'range']
                          for suffix in ('_mismatches', '_mismatch_indexes')}
        observed_fields = {key for key in report if key.endswith(('_mismatches', '_mismatch_indexes')) or key == 'mismatch_indexes'}
        require(observed_fields == mismatch_fields and all(report[key] == [] for key in mismatch_fields), 'library_mismatch')
        for key in ('fixture_sha256', 'library_sha256', 'go_oracle_sha256', 'framework_library_sha256'):
            require(hash_value(report.get(key)), 'library_byte_identity')
        return {'checks': 37, 'records': 1}
    controls = ['verified-cold', 'verified-warm', 'fresh-consumer', 'zip-mismatch',
                'mod-mismatch', 'invalid-signature', 'authority-unavailable']
    require(type(report.get('schema')) is int and report['schema'] == 1 and report.get('required_controls') == controls
            and report.get('controls') == dict.fromkeys(controls, 'passed')
            and report.get('go_version') == '1.27.3' and hash_value(report.get('go_binary_sha256')), 'strict_client_controls')
    require(report.get('script_sha256') == hashlib.sha256(source('scripts/test_go_checksum_client.py')).hexdigest()
            and report.get('fixture_sha256') == hashlib.sha256(source('internal/server/testdata/go-checksum-public.json')).hexdigest(), 'strict_client_byte_identity')
    require(report.get('zip_rejected_first') is True and report.get('untrusted_zip_sum_retained') is False
            and report.get('retry_succeeded') is False
            and report.get('altered_inert_file_extracted') is False, 'strict_client_trust_state')
    return {'checks': 7, 'records': 1}


def validate_summary(summary, candidate, run_id, spec, baselines, source=None):
    identity(summary, candidate, run_id, spec)
    require(set(summary) == {'candidate', 'run_id', 'runner_os', 'runner_arch', 'generated_at', 'records', 'limits'}, 'summary_fields')
    records = summary['records']
    require(isinstance(records, list) and 0 < len(records) <= 100, 'summary_record_inventory')
    observed = []
    portable = None
    common_portable = None
    candidate_binaries = None
    pins = {row['binary']: row['source'] for row in baselines}
    expected_baselines = {(row['schema'], row['source']) for row in baselines}
    _, os_name, arch_name = spec['platform']
    arch = {'X64': 'amd64', 'ARM64': 'arm64'}[arch_name]
    for record in records:
        require(isinstance(record, dict) and BASE_FIELDS <= set(record)
                and not set(record) - BASE_FIELDS - EXTRA_FIELDS, 'record_fields')
        require(record['status'] == 'passed' and hash_value(record['raw_report_sha256'])
                and record['source_dirty'] is not True, 'record_incomplete')
        name = record['report']
        require(isinstance(name, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,127}\.json', name), 'record_name')
        for key in ('checks', 'cases'):
            require(record[key] is None or type(record[key]) is int and 0 < record[key] <= 1000000, 'record_count')
        require(record['checks'] is not None or record['cases'] is not None, 'empty_record')
        for key, validate in CONTRACTS.items():
            if key in record:
                try:
                    require(validate(record[key], 'passed') == record[key], 'typed_report_contract')
                except (ValueError, TypeError, KeyError):
                    require(False, 'typed_report_contract')
        artifacts = record.get('artifacts', [])
        require(isinstance(artifacts, list) and len(artifacts) <= 16, 'binary_inventory')
        seen = set()
        for artifact in artifacts:
            require(isinstance(artifact, dict) and artifact.get('path') not in seen
                    and hash_value(artifact.get('sha256')), 'binary_identity')
            path = artifact['path']
            seen.add(path)
            if path == '.cache/bin/oras':
                require(set(artifact) == {'path', 'sha256'}, 'binary_identity')
                continue
            expected = candidate if path in ('.cache/ci-build/cratectl', '.cache/ci-build/cratectld') else pins.get(path)
            require(expected is not None and set(artifact) == {'path', 'sha256', 'build'}
                    and artifact['build'] == {'GOARCH': arch, 'GOOS': 'linux' if os_name == 'Linux' else 'darwin',
                                              'vcs.modified': 'false', 'vcs.revision': expected}, 'binary_source_identity')
        if spec['kind'] != 'security' and not (spec['kind'] == 'upgrades' and name.startswith('historical-build-')):
            required_binaries = {'.cache/ci-build/cratectl', '.cache/ci-build/cratectld'}
            require(required_binaries <= seen, 'candidate_binary_inventory_missing')
            current = {a['path']: a['sha256'] for a in artifacts if a['path'] in required_binaries}
            require(candidate_binaries is None or candidate_binaries == current, 'candidate_binary_identity_changed')
            candidate_binaries = current
        if artifacts:
            require(record['source_dirty'] is False and record['build_source_matches_candidate'] is True, 'binary_source_identity')
        if 'browser' in record:
            browser = record['browser']
            expected = 19 if spec['kind'] == 'native' else 1
            require(browser == {'expected': expected, 'unexpected': 0, 'skipped': 0, 'flaky': 0}, 'browser_incomplete')
        if 'baselines' in record:
            rows = record['baselines']
            require(isinstance(rows, list) and len(rows) == len(baselines)
                    and all(isinstance(row, dict) and set(row) == {'schema', 'source', 'binary_sha256'} and hash_value(row['binary_sha256']) for row in rows)
                    and {(row['schema'], row['source']) for row in rows} == expected_baselines, 'historical_baselines')
        if 'expected_schema' in record and source is not None and hasattr(source, 'schema'):
            require(record['expected_schema'] == source.schema, 'upgrade_schema_target')
        if 'go_export_portability_contract' in record:
            require(portable is None, 'portable_inventory')
            portable = record['go_export_portability_contract']
            require(portable['role'] == spec['kind'] and portable['source_run_id'] == str(run_id), 'portable_identity')
            if source is not None:
                require(portable['script_sha256'] == hashlib.sha256(source('scripts/conformance_go_export_portable.py')).hexdigest()
                        and portable['fixture_source_sha256'] == hashlib.sha256(source('internal/store/go_module_offline_integration_test.go')).hexdigest(), 'portable_source_identity')
        if 'go_common_export_portability_contract' in record:
            require(common_portable is None, 'common_portable_inventory')
            common_portable = record['go_common_export_portability_contract']
            require(common_portable['role'] == spec['kind'] and common_portable['source_run_id'] == str(run_id), 'common_portable_identity')
            if source is not None:
                bindings = {'script_sha256': 'scripts/conformance_go_common_export_portable.py',
                            'fixture_source_sha256': 'internal/server/go_module_export_collect_integration_test.go',
                            'capsule_source_sha256': 'internal/server/go_module_export_common_portable_integration_test.go',
                            'graph_fixture_source_sha256': 'internal/server/go_common_graph_fixture_test.go',
                            'native_helper_sha256': 'scripts/ci/go_set_offline_native.py',
                            'process_helper_sha256': 'scripts/ci/owned_child_process.py',
                            'decoder_sha256': 'scripts/go_common_export_fixture.py'}
                require(all(common_portable[key] == hashlib.sha256(source(path)).hexdigest() for key, path in bindings.items()), 'common_portable_source_identity')
        if 'go_module_contract' in record and source is not None:
            fixture = source('scripts/conformance_go.py')
            contract = record['go_module_contract']
            require(contract['fixture_source_sha256'] == hashlib.sha256(fixture).hexdigest(), 'go_fixture_source_identity')
            require(all(contract['publisher_sha256'].get(key) == value for key, value in go_deterministic_bindings(fixture).items()), 'go_publisher_fixture_identity')
        observed.append(record)

    kind = spec['kind']
    required = {'go': ('go_module_contract', 312), 'gradle': ('gradle_contract', 199),
                'ivy': ('ivy_contract', 666), 'sbt': ('sbt_contract', 269),
                'producer': ('go_export_portability_contract', 3), 'consumer': ('go_export_portability_contract', 13)}
    requires_common = source is not None and 'scripts/conformance_go_common_export_portable.py' in getattr(source, 'paths', ())
    if kind in ('producer', 'consumer') and requires_common:
        old = [r for r in observed if 'go_export_portability_contract' in r]
        common = [r for r in observed if 'go_common_export_portability_contract' in r]
        require(len(observed) == 2 and len(old) == len(common) == 1 and old[0] is not common[0]
                and old[0]['checks'] == (3 if kind == 'producer' else 13)
                and common[0]['checks'] == (4 if kind == 'producer' else 14), 'common_profile_report_inventory')
    elif kind in required:
        field, count = required[kind]
        require(len(observed) == 1 and field in observed[0] and observed[0]['checks'] == count, 'profile_report_inventory')
    elif kind == 'security':
        require(len(observed) == 1 and observed[0]['report'] == 'gitleaks-rule-fixtures.json' and observed[0]['cases'] == 324, 'security_report_inventory')
    elif kind == 'native':
        expected = dict(NATIVE_COUNTS)
        if arch == 'amd64':
            expected['console'] = 151
        counts = {}
        for record in observed:
            prefix = next((key for key in expected if record['report'].startswith(key + '-')), None)
            require(prefix is not None and prefix not in counts, 'native_report_inventory')
            counts[prefix] = record['checks']
            if prefix == 'console':
                require('browser' in record and record.get('workflow') == 'all', 'browser_incomplete')
            if prefix == 'conformance':
                require('maven_cache_contract' in record and 'journal_checkpoint_contract' in record, 'native_report_contracts')
        require(counts == expected, 'native_report_counts')
    elif kind == 'oci':
        require(len(observed) == 1 and observed[0]['checks'] == 214 and observed[0].get('phase') == 'complete', 'oci_report_inventory')
        record = observed[0]
        require(set(record.get('client_versions', {})) == {'docker', 'docker_engine', 'buildx', 'podman', 'helm'}
                and set(record.get('client_binary_sha256', {})) == {'docker', 'podman', 'helm'}
                and all(hash_value(v) for v in record['client_binary_sha256'].values())
                and record.get('client_packages', {}).get('podman', {}).get('architecture') == arch
                and isinstance(record.get('subjects'), list) and 0 < len(record['subjects']) <= 32, 'oci_client_identity')
    elif kind == 'upgrades':
        require(len(observed) == len(baselines) + 5, 'upgrade_report_inventory')
        history = [r for r in observed if r['report'].startswith('historical-build-')]
        lifecycle = [r for r in observed if r['report'].startswith('lifecycle-')]
        require(len(history) == 1 and 'baselines' in history[0] and history[0]['checks'] == len(baselines)
                and len(lifecycle) == len(baselines)-1 and {r.get('baseline_version') for r in lifecycle} == {b['schema'] for b in baselines if b['schema'] is not None}, 'upgrade_baseline_inventory')
        historical_hashes = {row['schema']: row['binary_sha256'] for row in history[0]['baselines']}
        historical_paths = {row['binary']: row['schema'] for row in baselines}
        for record in lifecycle:
            version = record['baseline_version']
            original = [a for a in record.get('artifacts', []) if a['path'] in historical_paths]
            require(len(original) == 1 and historical_paths[original[0]['path']] == version
                    and original[0]['sha256'] == historical_hashes[version], 'upgrade_historical_binary_identity')
        for version, checks in [(13, 70), (14, 81), (15, 96)] + ([(16, 96)] if any(b["schema"] == 16 for b in baselines) else []) + ([(17, 122)] if any(b["schema"] == 17 for b in baselines) else []):
            require(next(r for r in lifecycle if r['baseline_version'] == version)['checks'] == checks, 'upgrade_baseline_checks')
        require({r['report'].split('-')[0] for r in observed} == {'historical', 'lifecycle', 'repairs', 'retention', 'schedules', 'schema'}, 'upgrade_report_inventory')
    elif kind.startswith('browser-'):
        journey = kind.removeprefix('browser-')
        require(len(observed) == 5 and all(r.get('workflow') == journey and 'browser' in r for r in observed), 'focused_browser_inventory')
    else:
        require(False, 'unsupported_report_profile')
    return {'records': len(observed), 'checks': sum(r['checks'] or r['cases'] or 0 for r in observed),
            'raw_report_sha256': [r['raw_report_sha256'] for r in observed]}, [portable, common_portable] if requires_common and kind in ('producer', 'consumer') else portable
