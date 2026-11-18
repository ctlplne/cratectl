# SPDX-License-Identifier: BUSL-1.1
"""Closed native NuGet flat-container evidence for isolated Linux runners."""
if __package__:
    from .terraform_provider_evidence import hashes, matches, postgres_version
else:
    from terraform_provider_evidence import hashes, matches, postgres_version


CHECKS = (
    'qualification source is clean',
    'qualification binaries embed exact clean source commit',
    'stock dotnet SDK executable is available',
    'stock dotnet SDK matches the exact repository pin',
    'admin: create nuget repository cratectl-nuget-proxy',
    'ungranted stock source and other tenant requests make no origin request',
    'reader receives the owned repository grant',
    'NuGet discovery advertises the scoped cratectl flat address',
    'stock dotnet fails closed with current package review unreviewed',
    'cold exact request stages the reviewed archive Cratectl.Proxy.Application',
    'cold exact request stages the reviewed archive Cratectl.Proxy.Dependency',
    'stock dotnet restore succeeds cold-dependency-catalog',
    'stock dotnet resolves the exact application and transitive dependency cold-dependency-catalog',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Application cold-dependency-catalog',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Dependency cold-dependency-catalog',
    'upstream requests stay on canonical indexes, archives and SHA-512 sidecars',
    'native manifest bytes come from the verified archive',
    'stock dotnet restore succeeds warm-restart',
    'stock dotnet resolves the exact application and transitive dependency warm-restart',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Application warm-restart',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Dependency warm-restart',
    'restart and warm restore make no origin transfer',
    'current exact denial applies to cached version advertisements and bytes',
    'stock dotnet fails closed with current package review denied',
    'current policy can restore the exact retained digest',
    'stock dotnet restore succeeds allowed-again',
    'stock dotnet resolves the exact application and transitive dependency allowed-again',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Application allowed-again',
    'stock dotnet retains exact package, manifest and inert content for Cratectl.Proxy.Dependency allowed-again',
    'repeated policy changes and isolated stock restores keep the warm origin idle',
)
FIXTURES = {
    "Cratectl.Proxy.Application": {
        "nupkg": "b335d0d33284ef2eb0ca5769aac956b9d06cea9adae419a8fd5d8fedaeec9f68",
        "nuspec": "298bd531f5c7cf2d3f6ed5a6f3bf33cbe5a30ef2fd742b69ace763857d58e647",
        "payload": "ae2c017908e46841bb160c8d72c0ef9bf7ba7915477a524fc75b2e79ca14476a"
    },
    "Cratectl.Proxy.Dependency": {
        "nupkg": "4a35b660ba9bc5af59075570ff8a0f45cf5984f28af2ea4c3e1d736933a9f879",
        "nuspec": "97e29cc1690c50545e14bbfded0e90e2ea821d5e0097e61df0f0d6f938c68fb0",
        "payload": "fdab4317d7cf1d0ff7a49d4d019fa4c56bda621661a5c914cb5303ad3e71b67e"
    }
}
PROFILE = 'cratectl-native-nuget-flat-proxy-v1'
DIGEST = '[a-f0-9]{64}'
SOURCE_PATHS = (
    '.github/workflows/nuget-proxy.yml', 'Makefile', 'go.mod', 'go.sum', 'global.json',
    'scripts/ci/qualify_nuget_proxy.py', 'scripts/ci/nuget_proxy_evidence.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/conformance.py', 'scripts/conformance_nuget_proxy.py',
    'scripts/qualification_contract.py', 'scripts/bounded_client.py',
    'internal/server/nuget.go', 'internal/server/nuget_proxy.go', 'internal/server/nuget_proxy_integration_test.go',
    'internal/server/resolve.go', 'internal/store/artifact_read.go', 'internal/store/nuget.go', 'internal/store/nuget_proxy.go',
    'internal/store/retrieval.go', 'internal/store/repository.go', 'internal/store/migrations.go', 'internal/store/store.go',
)
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty',
          'source_sha256', 'binary_sha256', 'postgres', 'database_safety', 'checks', 'nuget_proxy',
          'goal_complete', 'broad_readiness'}


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != PROFILE or report['status'] != 'passed' or report['database_safety'] is not True
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or not hashes(report['source_sha256'], SOURCE_PATHS)
            or not postgres_version(report['postgres']) or report['checks'] != list(CHECKS)):
        raise ValueError('invalid native NuGet flat-container identity or coverage')
    native = report['nuget_proxy']
    if (type(native) is not dict or set(native) != {'sdk', 'dotnet_sha256', 'fixtures', 'loopback_http', 'origin_requests'}
            or native['sdk'] != '10.0.403' or not matches(native['dotnet_sha256'], DIGEST) or native['fixtures'] != FIXTURES
            or native['loopback_http'] is not True or type(native['origin_requests']) is not int or native['origin_requests'] != 6):
        raise ValueError('invalid stock NuGet or controlled origin identity')
    return report
