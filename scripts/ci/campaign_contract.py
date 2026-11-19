#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Reviewed native job inventory. Changes require matching workflow qualification."""

WORKFLOWS = {
    'ci.yml': 'main', 'go-modules.yml': 'go', 'jvm-clients.yml': 'jvm',
    'oci-clients.yml': 'oci', 'upgrade-qualification.yml': 'upgrades',
    'go-export-portability.yml': 'portable', 'nuget-contract.yml': 'library',
    'browser-repair.yml': 'browser', 'go-checksum-client.yml': 'strict', 'windows-cli.yml': 'windows',
    'compose-evaluation.yml': 'compose', 'linux-install.yml': 'linux-install', 'offline-media.yml': 'offline-media',
    'terraform-provider.yml': 'terraform-provider', 'cargo.yml': 'cargo', 'cargo-public.yml': 'cargo-public',
    'npm-search.yml': 'npm-search', 'python-search.yml': 'python-search', 'oci-repository-catalog.yml': 'oci-catalog',
    'maven-index.yml': 'maven-index', 'nuget-proxy.yml': 'nuget-proxy', 'nuget-public.yml': 'nuget-public',
}
PLATFORMS = {'amd64': ('ubuntu-24.04', 'Linux', 'X64'),
             'arm64': ('ubuntu-24.04-arm', 'Linux', 'ARM64'),
             'darwin-arm64': ('macos-15', 'macOS', 'ARM64')}
VALIDATOR_FILES = ['scripts/ci/' + name + '_evidence.py' for name in
                   ['maven', 'gradle', 'ivy', 'sbt', 'go_module', 'journal', 'go_export_portability', 'go_common_export_portability', 'go_requirement_export_portability', 'windows_cli', 'compose']]
LINUX_INSTALL_CONTRACT = {'.github/workflows/linux-install.yml', 'scripts/ci/linux_install_evidence.py'}
OFFLINE_MEDIA_CONTRACT = {'.github/workflows/offline-media.yml', 'scripts/ci/offline_media_evidence.py'}
TERRAFORM_PROVIDER_CONTRACT = {'.github/workflows/terraform-provider.yml', 'scripts/ci/terraform_provider_evidence.py'}
CARGO_CONTRACT = {'.github/workflows/cargo.yml', 'scripts/ci/cargo_evidence.py', 'scripts/ci/bootstrap_cargo.py'}
CARGO_PUBLIC_CONTRACT = {'.github/workflows/cargo-public.yml', 'scripts/ci/cargo_public_evidence.py'}
NPM_SEARCH_CONTRACT = {'.github/workflows/npm-search.yml', 'scripts/ci/npm_search_evidence.py'}
PYTHON_SEARCH_CONTRACT = {'.github/workflows/python-search.yml', 'scripts/ci/python_search_evidence.py'}
OCI_CATALOG_CONTRACT = {'.github/workflows/oci-repository-catalog.yml', 'scripts/ci/oci_repository_catalog_evidence.py'}
MAVEN_INDEX_CONTRACT = {'.github/workflows/maven-index.yml', 'scripts/ci/maven_index_evidence.py'}
NUGET_PROXY_CONTRACT = {'.github/workflows/nuget-proxy.yml', 'scripts/ci/nuget_proxy_evidence.py'}
NUGET_PUBLIC_CONTRACT = {'.github/workflows/nuget-public.yml', 'scripts/ci/nuget_public_evidence.py'}
OPTIONAL_CONTRACTS = (LINUX_INSTALL_CONTRACT, OFFLINE_MEDIA_CONTRACT, TERRAFORM_PROVIDER_CONTRACT,
                      CARGO_CONTRACT, CARGO_PUBLIC_CONTRACT, NPM_SEARCH_CONTRACT, PYTHON_SEARCH_CONTRACT, OCI_CATALOG_CONTRACT,
                      MAVEN_INDEX_CONTRACT, NUGET_PROXY_CONTRACT, NUGET_PUBLIC_CONTRACT)
OPTIONAL_FILES = set.union(*OPTIONAL_CONTRACTS)
COMPATIBLE_FILES = ['.github/workflows/' + name for name in WORKFLOWS
                    if '.github/workflows/' + name not in OPTIONAL_FILES
                    ] + VALIDATOR_FILES + ['scripts/ci/evidence_summary.py', 'scripts/conformance_go.py']


def jobs(family, schema=17, requirement_portability=False):
    if schema not in (17, 18, 19):
        raise ValueError('Unreviewed schema job contract')
    if type(requirement_portability) is not bool or requirement_portability and schema < 18:
        raise ValueError('Requirement portability needs its reviewed schema 18 or 19 contract')
    result = {}

    def add(name, arch, required, artifact=None, kind=None):
        result[name] = {'platform': PLATFORMS[arch], 'arch': arch,
                        'required': required, 'artifact': artifact, 'kind': kind}

    if family == 'main':
        add('Select runtime qualification inputs', 'amd64', ['Select from exact bounded Git changes'], 'ci-selection', 'selection')
        add('Scoped source, binary and history scans', 'amd64',
            ['Build binaries and scan called Go symbols', 'Scan current tree and complete reachable history for secrets',
             'Exercise narrow secret-rule exceptions with synthetic fixtures', 'Prepare bounded security evidence summary'],
            'ci-summary-security', 'security')
        for arch in PLATFORMS:
            add('Source and unit (' + arch + ')', arch, ['Build, unit, race and lint', 'npm dependency audit'], kind='source')
            add('Bounded native Go fuzz (' + arch + ')', arch,
                ['Exercise every checked-in fuzz target on this native runner'], kind='fuzz')
    for arch in ('amd64', 'arm64'):
        if family == 'main':
            required = ['Real PostgreSQL integration and timing', 'Real PostgreSQL integration with Go race detector',
                        'Stock client compatibility on real registry', 'Native lifecycle with curl, npm, pip, twine and Maven',
                        'Blank database initialization and trusted TLS client journey', 'Durable jobs and interrupted upload leases',
                        'Filesystem inventory and integrity sweeps', 'Cross-reference legal-hold matters', 'Prepare bounded native evidence summary']
            if arch == 'amd64':
                required.append('Chromium console workflows and accessibility')
            add('Real PostgreSQL and stock clients (' + arch + ')', arch, required, 'ci-summary-' + arch, 'native')
        elif family == 'go':
            add('Stock Go hosted and group modules (' + arch + ')', arch,
                ['Real PostgreSQL Go module regressions', 'Real PostgreSQL Go module regressions with race detector',
                 'Trusted TLS stock Go transitive downloads and policy recovery', 'Prepare bounded native evidence summary'],
                'ci-summary-go-module-' + arch, 'go')
        elif family == 'jvm':
            for title, short, command in [('Real Gradle publication and resolution', 'gradle', 'Stock Gradle publication, module/POM resolution, policy and recovery'),
                                          ('Real Ant and Ivy publication and resolution', 'ivy', 'Stock Ivy publication, transitive resolution, policy and recovery')]:
                add(title + ' (' + arch + ')', arch, [command, 'Prepare bounded native evidence summary'], 'ci-summary-' + short + '-' + arch, short)
            for series in ('sbt1', 'sbt2'):
                add('Real SBT publication and resolution (' + series + ' ' + arch + ')', arch,
                    ['Stock SBT publication, transitive resolution, policy and recovery', 'Prepare bounded native evidence summary'],
                    'ci-summary-' + series + '-' + arch, 'sbt')
        elif family == 'oci':
            add('Docker, Podman and Helm (' + arch + ')', arch,
                ['Publish and consume with native Docker, Podman and Helm', 'Prepare bounded evidence summary'], 'ci-summary-oci-clients-' + arch, 'oci')
        elif family == 'upgrades':
            add('Real PostgreSQL controlled upgrades (' + arch + ')', arch,
                ['Rebuild and verify every pinned historical native server', 'Legacy adoption with actual migration process interruption',
                 'Retained lifecycle through every schema 2–' + str(schema - 1) + ' upgrade', 'Repair and recurring integrity upgrades',
                 'Retention and scheduled-retirement upgrades', 'Prepare bounded upgrade evidence summary'], 'ci-summary-upgrades-' + arch, 'upgrades')
        elif family == 'library':
            add('Actual NuGet libraries versus Go (' + arch + ')', arch,
                ['Compare actual native libraries without remote package restore'], 'ci-summary-nuget-version-' + arch, 'library')
        elif family == 'compose':
            add('Blank Compose registry and stock npm (' + arch + ')', arch,
                ['Replay blank Compose with real PostgreSQL, TLS and stock npm'], 'ci-summary-compose-' + arch, 'compose')
        elif family == 'linux-install':
            add('Network-isolated Linux binary installation (' + arch + ')', arch,
                ['Prepare reviewed inputs before the isolated installation',
                 'Verify and install both executables in a network-isolated target'],
                'ci-summary-linux-install-' + arch, 'linux-install')
        elif family == 'offline-media':
            add('Signed media and imported registry (' + arch + ')', arch,
                ['Prepare pinned tools and images before isolation',
                 'Authenticate and load media and replay stock npm without network access'],
                'ci-summary-offline-media-' + arch, 'offline-media')
        elif family == 'terraform-provider':
            add('Terraform and OpenTofu with real PostgreSQL (' + arch + ')', arch,
                ['Prepare pinned stock infrastructure clients', 'Build and test the isolated provider module',
                 'Replay stock saved plans, imports and drift with real PostgreSQL'],
                'ci-summary-terraform-provider-' + arch, 'terraform-provider')
        elif family == 'cargo':
            add('Stock Cargo and real PostgreSQL (' + arch + ')', arch,
                ['Prepare the digest-pinned stock Cargo SDK', 'Build the clean cratectl candidate',
                 'Replay authenticated Cargo publish and fetch against real PostgreSQL'],
                'ci-summary-cargo-' + arch, 'cargo')
        elif family == 'cargo-public':
            add('Stock Cargo canonical lockfile replacement (' + arch + ')', arch,
                ['Prepare the digest-pinned stock Cargo SDK', 'Build the clean cratectl candidate',
                 'Replay the actual public Cargo graph and canonical lockfile'],
                'ci-summary-cargo-public-' + arch, 'cargo-public')
        elif family == 'npm-search':
            add('Stock npm search and real PostgreSQL (' + arch + ')', arch,
                ['Build the clean cratectl candidate', 'Replay hosted and cached search with stock npm'],
                'ci-summary-npm-search-' + arch, 'npm-search')
        elif family == 'python-search':
            add('Stock Python search and real PostgreSQL (' + arch + ')', arch,
                ['Prepare pinned stock pip and Twine', 'Build the clean cratectl candidate',
                 'Replay hosted and cached search with stock pip and Twine'],
                'ci-summary-python-search-' + arch, 'python-search')
        elif family == 'oci-catalog':
            add('Stock ORAS repository catalog and real PostgreSQL (' + arch + ')', arch,
                ['Prepare digest-pinned stock ORAS', 'Build the clean cratectl candidate',
                 'Replay authorized OCI catalog discovery with stock ORAS'],
                'ci-summary-oci-catalog-' + arch, 'oci-catalog')
        elif family == 'maven-index':
            add('Stock Maven Indexer and real PostgreSQL (' + arch + ')', arch,
                ['Fetch the digest-pinned Apache Maven Indexer Reader', 'Build the clean cratectl candidate',
                 'Replay the hosted index with the stock Apache reader'], 'ci-summary-maven-index-' + arch, 'maven-index')
        elif family == 'nuget-proxy':
            add('Stock NuGet proxy and real PostgreSQL (' + arch + ')', arch,
                ['Build the clean cratectl candidate', 'Replay stock dotnet against the governed NuGet proxy'],
                'ci-summary-nuget-proxy-' + arch, 'nuget-proxy')
        elif family == 'nuget-public':
            add('Stock public NuGet lockfile and real PostgreSQL (' + arch + ')', arch,
                ['Build the clean cratectl candidate', 'Replay stock dotnet against the public NuGet.org origin'],
                'ci-summary-nuget-public-' + arch, 'nuget-public')
    if family == 'portable':
        add('Real PostgreSQL signed export source (amd64)', 'amd64',
            ['Prepare actual signed source fixture and independent trust-channel digests', 'Transfer reviewed synthetic fixture only',
             'Prepare complete common collection and separate trust-channel digests', 'Transfer reviewed common collection fixture only',
             'Prepare bounded source evidence summary'],
            'ci-summary-export-portability-producer', 'producer')
        add('Independent signed export consumer (arm64)', 'arm64',
            ['Receive the exact source artifact', 'Independently verify, install inert bytes and reject changed inputs',
             'Receive the exact common collection artifact', 'Independently verify complete common graph and native interruption controls',
             'Prepare bounded destination evidence summary'],
            'ci-summary-export-portability-consumer', 'consumer')
        if requirement_portability:
            result['Real PostgreSQL signed export source (amd64)']['required'] += [
                'Prepare signed requirement collection and separate trust-channel digests',
                'Transfer reviewed requirement collection fixture only']
            result['Independent signed export consumer (arm64)']['required'] += [
                'Receive the exact requirement collection artifact',
                'Independently replay requirement originals and native acknowledgement loss']
    if family == 'browser':
        for journey in ('repair', 'retention', 'nuget'):
            add('Real x86 Chromium ' + journey + ' replay', 'amd64',
                ['Replay selected journey five times with independent fresh databases', 'Prepare bounded evidence summary'],
                'ci-summary-' + journey + '-browser', 'browser-' + journey)
    if family == 'strict':
        for arch in PLATFORMS:
            label = arch if arch.startswith('darwin') else 'linux-' + arch
            add('Stock Go checksum-on trust-state controls (' + label + ')', arch,
                ['Check bounded evidence export with stand-ins', 'Check actual stock Go checksum and failed-cache behavior'],
                'ci-summary-checksum-client-' + label, 'strict')
    if family == 'windows':
        for arch, runner, machine in [('amd64', 'windows-2025', 'X64'), ('arm64', 'windows-11-arm', 'ARM64')]:
            result['Native Windows private configuration (' + arch + ')'] = {
                'platform': (runner, 'Windows', machine), 'arch': arch,
                'required': ['Preserve exact Git source bytes', 'Build exact native CLI and qualification driver',
                             'Run native private-file CLI and owned-job regressions'],
                'artifact': 'ci-summary-windows-cli-' + arch, 'kind': 'windows'}
    return result
