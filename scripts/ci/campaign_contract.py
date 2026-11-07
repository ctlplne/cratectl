#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Reviewed native job inventory. Changes require matching workflow qualification."""

WORKFLOWS = {
    'ci.yml': 'main', 'go-modules.yml': 'go', 'jvm-clients.yml': 'jvm',
    'oci-clients.yml': 'oci', 'upgrade-qualification.yml': 'upgrades',
    'go-export-portability.yml': 'portable', 'nuget-contract.yml': 'library',
    'browser-repair.yml': 'browser', 'go-checksum-client.yml': 'strict',
}
PLATFORMS = {'amd64': ('ubuntu-24.04', 'Linux', 'X64'),
             'arm64': ('ubuntu-24.04-arm', 'Linux', 'ARM64'),
             'darwin-arm64': ('macos-15', 'macOS', 'ARM64')}
VALIDATOR_FILES = ['scripts/ci/' + name + '_evidence.py' for name in
                   ['maven', 'gradle', 'ivy', 'sbt', 'go_module', 'journal', 'go_export_portability']]
COMPATIBLE_FILES = ['.github/workflows/' + name for name in WORKFLOWS] + VALIDATOR_FILES + ['scripts/ci/evidence_summary.py', 'scripts/conformance_go.py']


def jobs(family):
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
                 'Retained lifecycle through every schema 2–15 upgrade', 'Repair and recurring integrity upgrades',
                 'Retention and scheduled-retirement upgrades', 'Prepare bounded upgrade evidence summary'], 'ci-summary-upgrades-' + arch, 'upgrades')
        elif family == 'library':
            add('Actual NuGet libraries versus Go (' + arch + ')', arch,
                ['Compare actual native libraries without remote package restore'], 'ci-summary-nuget-version-' + arch, 'library')
    if family == 'portable':
        add('Real PostgreSQL signed export source (amd64)', 'amd64',
            ['Prepare actual signed source fixture and independent trust-channel digests', 'Transfer reviewed synthetic fixture only', 'Prepare bounded source evidence summary'],
            'ci-summary-export-portability-producer', 'producer')
        add('Independent signed export consumer (arm64)', 'arm64',
            ['Receive the exact source artifact', 'Independently verify, install inert bytes and reject changed inputs', 'Prepare bounded destination evidence summary'],
            'ci-summary-export-portability-consumer', 'consumer')
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
    return result
