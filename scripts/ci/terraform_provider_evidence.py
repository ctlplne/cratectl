# SPDX-License-Identifier: BUSL-1.1
"""Closed safe evidence contract for the native Terraform and OpenTofu profile."""
import re


CLIENTS = {'terraform': '1.17.2', 'tofu': '1.13.9'}
ARCHIVE_PINS = {
    'amd64': {'terraform': 'e6f16b2f0b137ee5729caa8c4e79a3bae4ee261acd198a1fcfa8584a6296605b',
              'tofu': 'bc44eb6b06446ba83bd4072114891987f590f66cca712737a7f1147c50c539ce'},
    'arm64': {'terraform': '858e08c181a76b6b223e8c767a8e983922eebe2d062db949a2de66ce040c368c',
              'tofu': '04f7c93828b859d420269ed30f923ffebf09157b5d7fb95bf8d88a4d208b7fa3'},
}
BASE_CHECKS = (
    'clean exact source', 'cratectl matches the clean candidate', 'cratectld matches the clean candidate',
    'real PostgreSQL 16.15', 'absent repository has an authority and tenant bound creation plan',
    'plan, wrong approval and denied callers leave the tenant journal unchanged',
    'concurrent approved requests produce one creation or a safe retry',
    'retry after successful creation returns unchanged', 'one repository creation event despite concurrent retry',
    'second tenant can plan an independent same-name repository', 'import returns the exact active hosted fields',
    'plan exposes review drift without writing', 'stock npm published its exact bytes and unassessed input was denied',
    'registry restart preserves the declared state', 'fresh stock npm downloads the exact approved archive after restart',
    'stale approval leaves suspended repository retained', 'suspended repository cannot be imported as active',
    'provider matches the clean candidate', 'revoked administrator cannot plan',
    'schema 18 with all 57 tenant tables forced RLS and a restricted runtime role',
)
CLIENT_CHECKS = (
    'saved stock plan binds tenant and registry authority', 'plan left the registry unchanged',
    'saved plan cannot apply to another bound authority', 'retry plan keeps the same reviewed repository identity',
    'stock apply created the exact hosted review configuration', 'competing creation is not silently adopted',
    'explicit import reads the exact existing repository', 'read-only refresh exposes exact lifecycle drift',
    'destroy fails and leaves the repository retained',
)
SOURCE_PATHS = (
    '.github/workflows/terraform-provider.yml', 'Makefile', 'go.mod', 'go.sum',
    'integrations/terraform/go.mod', 'integrations/terraform/go.sum', 'integrations/terraform/main.go',
    'integrations/terraform/provider.go', 'integrations/terraform/repository.go', 'integrations/terraform/repository_test.go',
    'internal/management/client.go', 'internal/management/repositories.go', 'cmd/cratectl/repository_manifest.go',
    'scripts/ci/bootstrap_iac_clients.py', 'scripts/ci/fetch_archive.py', 'scripts/ci/terraform_provider_evidence.py',
    'scripts/conformance_repository_manifest.py', 'scripts/terraform_repository_fixture.py',
    'scripts/qualification_contract.py', 'scripts/bounded_client.py',
)
FIELDS = {'schema', 'profile', 'candidate', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'status',
          'client_archives', 'clients', 'checks', 'source_sha256', 'binary_sha256', 'provider_sha256',
          'archive_sha256', 'postgres', 'npm', 'goal_complete', 'broad_readiness'}


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def hashes(value, names):
    return type(value) is dict and set(value) == set(names) and all(matches(x, '[a-f0-9]{64}') for x in value.values())


def postgres_version(value):
    return matches(value, r'postgres \(PostgreSQL\) 16\.15(?: \([^\r\n]{1,100}\))?')


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != 'cratectl-native-terraform-provider-v1'
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['status'] != 'passed'
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or report['checks'] != list(BASE_CHECKS) or not postgres_version(report['postgres'])
            or not matches(report['npm'], r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            or not hashes(report['source_sha256'], SOURCE_PATHS)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld'))
            or not matches(report['provider_sha256'], '[a-f0-9]{64}')
            or not matches(report['archive_sha256'], '[a-f0-9]{64}')):
        raise ValueError('invalid native provider evidence')
    arch = 'amd64' if report['runner_arch'] == 'X64' else 'arm64'
    if report['client_archives'] != ARCHIVE_PINS[arch] or type(report['clients']) is not list or len(report['clients']) != len(CLIENTS):
        raise ValueError('invalid native provider client inventory')
    for row, (name, version) in zip(report['clients'], CLIENTS.items(), strict=True):
        if (type(row) is not dict or set(row) != {'client', 'version', 'client_sha256', 'checks'}
                or row['client'] != name or row['version'] != version
                or not matches(row['client_sha256'], '[a-f0-9]{64}') or row['checks'] != list(CLIENT_CHECKS)):
            raise ValueError('invalid native provider client result')
    return report
