#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Retained public report fixtures and owned mutations, without native execution."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from campaign_contract import WORKFLOWS, jobs
from campaign_reports import validate_custom, validate_summary
from campaign_transport import EvidenceError
from compose_evidence import CHECKS as COMPOSE_CHECKS, SOURCE_PATHS as COMPOSE_FILES
from debian_apt_evidence import (APT_CHECKS as DEBIAN_APT_CHECKS, BASE_CHECKS as DEBIAN_APT_BASE,
                                 PROFILE as DEBIAN_APT_PROFILE, SOURCE_PATHS as DEBIAN_APT_FILES,
                                 APT_SUITE_CHECKS as DEBIAN_SUITE_CHECKS, SUITE_PROFILE as DEBIAN_SUITE_PROFILE,
                                 SUITE_SOURCE_PATHS as DEBIAN_SUITE_FILES)
from composer_hosted_evidence import (BASE_CHECKS as COMPOSER_BASE, CHECKS as COMPOSER_CHECKS,
                                      COMPOSER_SHA256, COMPOSER_VERSION, COORDINATES as COMPOSER_COORDINATES,
                                      FILES as COMPOSER_FILES, PROFILE as COMPOSER_PROFILE,
                                      GROUP_CHECKS as COMPOSER_GROUP_CHECKS, GROUP_FILES as COMPOSER_GROUP_FILES,
                                      GROUP_PROFILE as COMPOSER_GROUP_PROFILE, VERSIONS_PROFILE as COMPOSER_VERSIONS_PROFILE,
                                      PROXY_CHECKS as COMPOSER_PROXY_CHECKS, PROXY_FILES as COMPOSER_PROXY_FILES,
                                      PROXY_PROFILE as COMPOSER_PROXY_PROFILE,
                                      SEARCH_CHECKS as COMPOSER_SEARCH_CHECKS, SEARCH_FILES as COMPOSER_SEARCH_FILES,
                                      SEARCH_PROFILE as COMPOSER_SEARCH_PROFILE, MATCH as COMPOSER_SEARCH_MATCH,
                                      LIFECYCLE_CHECKS as COMPOSER_LIFECYCLE_CHECKS, LIFECYCLE_FILES as COMPOSER_LIFECYCLE_FILES,
                                      LIFECYCLE_PROFILE as COMPOSER_LIFECYCLE_PROFILE,
                                      NEIGHBOR as COMPOSER_SEARCH_NEIGHBOR, HIDDEN as COMPOSER_SEARCH_HIDDEN,
                                      EXTRA_COORDINATES as COMPOSER_EXTRA_COORDINATES, VERSION_CHECKS as COMPOSER_VERSION_CHECKS)
from conda_hosted_evidence import (BASE_CHECKS as CONDA_BASE, CHECKS as CONDA_CHECKS, FILES as CONDA_FILES,
                                  PROFILE as CONDA_PROFILE, PINS as CONDA_PINS, VERSION as CONDA_VERSION, fixtures as conda_fixtures)
from cran_hosted_evidence import (BASE_CHECKS as CRAN_BASE, CHECKS as CRAN_CHECKS, FILES as CRAN_FILES, PROFILE as CRAN_PROFILE,
                                 INSTALL_CHECKS as CRAN_INSTALL_CHECKS, INSTALL_FILES as CRAN_INSTALL_FILES,
                                 INSTALL_PROFILE as CRAN_INSTALL_PROFILE, LAUNCHER as CRAN_LAUNCHER,
                                 HISTORY_CHECKS as CRAN_HISTORY_CHECKS, GROUP_CHECKS as CRAN_GROUP_CHECKS,
                                 PROFILES as CRAN_PROFILES, PROXY_CHECKS as CRAN_PROXY_CHECKS, source_files as cran_source_files)
from cran_hosted_fixture import (COORDINATES as CRAN_COORDINATES, LATEST as CRAN_LATEST, EARLIER as CRAN_EARLIER,
                                 SELECTED_LIBRARY as CRAN_LIBRARY, TOOLS as CRAN_TOOLS,
                                 filename as cran_filename, make_archive as cran_archive)
from cran_group_fixture import LOWER_ONLY as CRAN_LOWER_ONLY, LOWER_VARIANT as CRAN_LOWER_VARIANT
from cran_proxy_fixture import REPLACEMENT as CRAN_PROXY_REPLACEMENT
from linux_install_evidence import CHECKS as INSTALL_CHECKS, IMAGE as INSTALL_IMAGE, SOURCE_PATHS as INSTALL_FILES
from maven_index_evidence import (BASE_CHECKS as MAVEN_INDEX_BASE, CACHED_CHECKS as MAVEN_CACHED_CHECKS,
                                  CACHED_PROFILE as MAVEN_CACHED_PROFILE, CACHED_SOURCE_PATHS as MAVEN_CACHED_FILES,
                                  GROUP_CHECKS as MAVEN_GROUP_CHECKS, INDEXER_SHA256, MAVEN_INDEX_CHECKS,
                                  PROFILE as MAVEN_INDEX_PROFILE, SOURCE_PATHS as MAVEN_INDEX_FILES)
from npm_search_evidence import BASE_CHECKS as NPM_BASE, HOSTED_CHECKS as NPM_HOSTED, CACHED_CHECKS as NPM_CACHED, SOURCE_PATHS as NPM_FILES
from nuget_proxy_evidence import (CHECKS as NUGET_PROXY_CHECKS, COMBINED_CHECKS as NUGET_COMBINED_CHECKS,
                                 COMBINED_PROFILE as NUGET_COMBINED_PROFILE, COMBINED_SOURCE_PATHS as NUGET_COMBINED_FILES,
                                 FIXTURES as NUGET_PROXY_FIXTURES, GROUP_FIXTURES as NUGET_GROUP_FIXTURES,
                                 PROFILE as NUGET_PROXY_PROFILE, SERVICE_INDEX_FIXTURE as NUGET_SERVICE_INDEX_FIXTURE,
                                 SOURCE_PATHS as NUGET_PROXY_FILES)
from nuget_public_evidence import (ARCHIVES as NUGET_PUBLIC_ARCHIVES, CHECKS as NUGET_PUBLIC_CHECKS,
                                  CONTENT as NUGET_PUBLIC_CONTENT, PROFILE as NUGET_PUBLIC_PROFILE,
                                  SOURCE_PATHS as NUGET_PUBLIC_FILES)
from oci_repository_catalog_evidence import (ARCHIVE_PINS as ORAS_PINS, BASE_CHECKS as OCI_CATALOG_BASE,
                                             CACHED_CHECKS as OCI_CACHED_CHECKS, CACHED_PROFILE as OCI_CACHED_PROFILE,
                                             CACHED_SOURCE_PATHS as OCI_CACHED_FILES, CATALOG_CHECKS, GROUP_CHECKS,
                                             SOURCE_PATHS as OCI_CATALOG_FILES)
from python_search_evidence import BASE_CHECKS as PYTHON_BASE, HOSTED_CHECKS as PYTHON_HOSTED, CACHED_CHECKS as PYTHON_CACHED, SOURCE_PATHS as PYTHON_FILES
from offline_media_evidence import CHECKS as OFFLINE_CHECKS, PHASES as OFFLINE_PHASES, SOURCE_PATHS as OFFLINE_FILES
from test_go_common_export_portability_evidence import complete as complete_common_contract
from test_go_requirement_export_portability_evidence import complete as complete_requirement_contract

ROOT = Path(__file__).resolve().parents[2]
SPECS = {spec['artifact']: spec for family in WORKFLOWS.values() for spec in jobs(family).values() if spec['artifact']}


class CampaignReports(unittest.TestCase):
    def test_cran_reports_require_the_native_r_distribution_and_exact_source_graph(self):
        def source(path):
            return path.encode()

        candidate = 'a' * 40
        version, distribution = CRAN_TOOLS['Linux', 'x86_64']
        packages = {cran_filename(c): hashlib.sha256(cran_archive(c)).hexdigest() for c in CRAN_COORDINATES}
        chosen = {cran_filename(c): packages[cran_filename(c)] for c in (CRAN_LATEST, CRAN_LIBRARY)}
        native = {'checks': list(CRAN_CHECKS), 'version': version, 'distribution_sha256': distribution,
                  'binary_sha256': 'f' * 64, 'archive_sha256': packages, 'selected': chosen}
        report = {'schema': 1, 'profile': CRAN_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'X64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in CRAN_FILES},
                  'binary_sha256': {'cratectl': 'd' * 64, 'cratectld': 'e' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.16', 'npm': '10.9.9', 'checks': list(CRAN_BASE),
                  'cran_hosted': native, 'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-cran-hosted-amd64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 29, 'records': 1})
        wrong_branch = {cran_filename(c): packages[cran_filename(c)] for c in (CRAN_EARLIER, CRAN_LIBRARY)}
        for patch in ({'distribution_sha256': CRAN_TOOLS['Linux', 'aarch64'][1]}, {'selected': wrong_branch},
                      {'checks': native['checks'][:-1]}):
            with self.assertRaisesRegex(EvidenceError, 'cran_hosted_report_contract'):
                validate_custom({**report, 'cran_hosted': {**native, **patch}}, candidate, 12, spec, source)

        def install_source(path):
            return b'--cran-install' if path == '.github/workflows/cran-hosted.yml' else source(path)

        installation = {'checks': list(CRAN_INSTALL_CHECKS), 'launcher_sha256': hashlib.sha256(install_source(CRAN_LAUNCHER)).hexdigest()}
        combined = {**report, 'profile': CRAN_INSTALL_PROFILE, 'cran_hosted': {**native, 'installation': installation},
                    'source_sha256': {path: hashlib.sha256(install_source(path)).hexdigest() for path in CRAN_INSTALL_FILES}}
        self.assertEqual(validate_custom(combined, candidate, 12, spec, install_source), {'checks': 31, 'records': 1})
        installation['launcher_sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'cran_hosted_report_contract'):
            validate_custom(combined, candidate, 12, spec, install_source)

        def history_source(path):
            return b'--cran-history' if path == '.github/workflows/cran-hosted.yml' else source(path)

        old = cran_filename(CRAN_EARLIER)
        archived = {'checks': list(CRAN_HISTORY_CHECKS), 'file': old, 'sha256': packages[old]}
        historical = {**report, 'profile': CRAN_PROFILES[False, True, False, False], 'cran_hosted': {**native, 'history': archived},
                      'source_sha256': {path: hashlib.sha256(history_source(path)).hexdigest() for path in cran_source_files(False, True)}}
        self.assertEqual(validate_custom(historical, candidate, 12, spec, history_source), {'checks': 34, 'records': 1})
        archived['file'] = cran_filename(CRAN_LATEST)
        with self.assertRaisesRegex(EvidenceError, 'cran_hosted_report_contract'):
            validate_custom(historical, candidate, 12, spec, history_source)

        def group_source(path):
            return b'--cran-group' if path == '.github/workflows/cran-hosted.yml' else source(path)

        group = {'checks': list(CRAN_GROUP_CHECKS), 'selected': chosen,
                 'lower_collision_sha256': hashlib.sha256(cran_archive(CRAN_LATEST, variant=CRAN_LOWER_VARIANT)).hexdigest(),
                 'lower_only_sha256': hashlib.sha256(cran_archive(CRAN_LOWER_ONLY)).hexdigest()}
        grouped = {**report, 'profile': CRAN_PROFILES[False, False, True, False], 'cran_hosted': {**native, 'group': group},
                   'source_sha256': {path: hashlib.sha256(group_source(path)).hexdigest() for path in cran_source_files(False, False, True)}}
        self.assertEqual(validate_custom(grouped, candidate, 12, spec, group_source), {'checks': 38, 'records': 1})
        group['selected'] = wrong_branch
        with self.assertRaisesRegex(EvidenceError, 'cran_hosted_report_contract'):
            validate_custom(grouped, candidate, 12, spec, group_source)

        def proxy_source(path):
            return b'--cran-proxy' if path == '.github/workflows/cran-hosted.yml' else source(path)

        replacement = hashlib.sha256(cran_archive(CRAN_LATEST, variant=CRAN_PROXY_REPLACEMENT)).hexdigest()
        proxy = {'checks': list(CRAN_PROXY_CHECKS), 'selected': chosen, 'replacement_sha256': replacement}
        proxied = {**report, 'profile': CRAN_PROFILES[False, False, False, True], 'cran_hosted': {**native, 'proxy': proxy},
                   'source_sha256': {path: hashlib.sha256(proxy_source(path)).hexdigest()
                                     for path in cran_source_files(False, False, False, True)}}
        self.assertEqual(validate_custom(proxied, candidate, 12, spec, proxy_source), {'checks': 41, 'records': 1})
        proxy['replacement_sha256'] = chosen[cran_filename(CRAN_LATEST)]
        with self.assertRaisesRegex(EvidenceError, 'cran_hosted_report_contract'):
            validate_custom(proxied, candidate, 12, spec, proxy_source)

    def test_conda_reports_bind_native_platform_and_exact_selected_builds(self):
        def source(path):
            return path.encode()

        candidate, platform = 'a' * 40, 'linux-aarch64'
        packages = conda_fixtures(platform)
        archives = {p.path: hashlib.sha256(p.archive()).hexdigest() for p in packages}
        chosen = {p.path: archives[p.path] for p in packages[:2]}
        native = {'checks': list(CONDA_CHECKS), 'subdir': platform, 'client_version': CONDA_VERSION,
                  'client_sha256': CONDA_PINS[platform], 'archive_sha256': archives, 'selected': chosen}
        report = {'schema': 1, 'profile': CONDA_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in CONDA_FILES},
                  'binary_sha256': {'cratectl': 'd' * 64, 'cratectld': 'e' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.16', 'npm': '10.9.9', 'checks': list(CONDA_BASE),
                  'conda_hosted': native, 'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-conda-hosted-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 30, 'records': 1})
        changed = {packages[0].path: chosen[packages[0].path], packages[2].path: archives[packages[2].path]}
        for patch in ({'client_sha256': CONDA_PINS['linux-64']}, {'selected': changed}, {'checks': native['checks'][:-1]}):
            with self.assertRaisesRegex(EvidenceError, 'conda_hosted_report_contract'):
                validate_custom({**report, 'conda_hosted': {**native, **patch}}, candidate, 12, spec, source)

    def test_composer_reports_bind_stock_resolution_and_policy_replay(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        native = {'checks': list(COMPOSER_CHECKS), 'composer_version': COMPOSER_VERSION, 'composer_sha256': COMPOSER_SHA256,
                  'php_version': '8.3.6', 'archive_sha256': {f'{name}@{version}': 'b' * 64 for name, version in COMPOSER_COORDINATES},
                  'lock_sha256': 'c' * 64}
        report = {'schema': 1, 'profile': COMPOSER_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in COMPOSER_FILES},
                  'binary_sha256': {'cratectl': 'd' * 64, 'cratectld': 'e' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(COMPOSER_BASE),
                  'composer_hosted': native, 'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-composer-hosted-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 34, 'records': 1})
        for patch in ({'composer_sha256': 'd' * 64}, {'checks': native['checks'][:-1]}):
            with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
                validate_custom({**report, 'composer_hosted': {**native, **patch}}, candidate, 12, spec, source)
        group_source = lambda path: b'--composer-group' if path == '.github/workflows/composer-hosted.yml' else source(path)
        group = {**native, 'checks': list(COMPOSER_GROUP_CHECKS), 'collision_sha256': 'f' * 64}
        combined = {**report, 'profile': COMPOSER_GROUP_PROFILE, 'composer_group': group,
                    'source_sha256': {path: hashlib.sha256(group_source(path)).hexdigest() for path in COMPOSER_GROUP_FILES}}
        self.assertEqual(validate_custom(combined, candidate, 12, spec, group_source), {'checks': 51, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
            validate_custom({**combined, 'composer_group': {**group, 'collision_sha256': 'b' * 64}}, candidate, 12, spec, group_source)

        version_source = lambda path: b'--composer-group --composer-versions' if path == '.github/workflows/composer-hosted.yml' else source(path)
        versions = {'checks': list(COMPOSER_VERSION_CHECKS),
                    'archive_sha256': {f'{name}@{version}': 'c' * 64 for name, version in COMPOSER_EXTRA_COORDINATES},
                    'development_lock_sha256': 'e' * 64, 'prerelease_lock_sha256': 'd' * 64}
        extended = {**combined, 'profile': COMPOSER_VERSIONS_PROFILE, 'composer_hosted': {**native, 'version_forms': versions},
                    'source_sha256': {path: hashlib.sha256(version_source(path)).hexdigest() for path in COMPOSER_GROUP_FILES}}
        self.assertEqual(validate_custom(extended, candidate, 12, spec, version_source), {'checks': 61, 'records': 1})
        wrong = {**versions, 'prerelease_lock_sha256': 'e' * 64}
        with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
            validate_custom({**extended, 'composer_hosted': {**native, 'version_forms': wrong}}, candidate, 12, spec, version_source)

        def proxy_source(path):
            return b'--composer-group --composer-versions --composer-proxy' if path == '.github/workflows/composer-hosted.yml' else source(path)

        proxy = {'checks': list(COMPOSER_PROXY_CHECKS), 'lock_sha256': 'c' * 64,
                 'archive_sha256': {'cratectl/composer-app': 'a' * 64, 'cratectl/composer-lib': 'd' * 64}}
        proxied = {**extended, 'profile': COMPOSER_PROXY_PROFILE, 'composer_proxy': proxy,
                   'source_sha256': {path: hashlib.sha256(proxy_source(path)).hexdigest() for path in COMPOSER_PROXY_FILES}}
        self.assertEqual(validate_custom(proxied, candidate, 12, spec, proxy_source), {'checks': 73, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
            validate_custom({**proxied, 'composer_proxy': {**proxy, 'checks': proxy['checks'][:-1]}}, candidate, 12, spec, proxy_source)
        discovery_source = lambda path: b'--composer-group --composer-versions --composer-proxy --composer-search' if path == '.github/workflows/composer-hosted.yml' else source(path)
        discovery = {'checks': list(COMPOSER_SEARCH_CHECKS), 'archive_sha256': {
            COMPOSER_SEARCH_MATCH: 'a' * 64, COMPOSER_SEARCH_NEIGHBOR: 'b' * 64, COMPOSER_SEARCH_HIDDEN: 'd' * 64}}
        discovered = {**proxied, 'profile': COMPOSER_SEARCH_PROFILE, 'composer_search': discovery,
                      'source_sha256': {path: hashlib.sha256(discovery_source(path)).hexdigest() for path in COMPOSER_SEARCH_FILES}}
        self.assertEqual(validate_custom(discovered, candidate, 12, spec, discovery_source), {'checks': 79, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
            validate_custom({**discovered, 'composer_search': {**discovery, 'checks': discovery['checks'][:-1]}}, candidate, 12, spec, discovery_source)
        def lifecycle_source(path):
            return discovery_source(path) + b' --composer-lifecycle' if path == '.github/workflows/composer-hosted.yml' else source(path)

        lifecycle = {'checks': list(COMPOSER_LIFECYCLE_CHECKS), 'restored_archive_sha256': discovery['archive_sha256'][COMPOSER_SEARCH_MATCH],
                     'unchanged_lock_sha256': 'e' * 64}
        recovered = {**discovered, 'profile': COMPOSER_LIFECYCLE_PROFILE, 'composer_search': {**discovery, 'lifecycle': lifecycle},
                     'source_sha256': {path: hashlib.sha256(lifecycle_source(path)).hexdigest() for path in COMPOSER_LIFECYCLE_FILES}}
        self.assertEqual(validate_custom(recovered, candidate, 12, spec, lifecycle_source), {'checks': 85, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'composer_hosted_report_contract'):
            broken = {**lifecycle, 'restored_archive_sha256': 'f' * 64}
            validate_custom({**recovered, 'composer_search': {**discovery, 'lifecycle': broken}}, candidate, 12, spec, lifecycle_source)

    def test_debian_apt_report_requires_signed_repository_controls_on_native_architecture(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        apt = {'checks': list(DEBIAN_APT_CHECKS), 'apt': 'apt 2.8.3 (arm64)', 'architecture': 'arm64',
               'gpg': 'gpg (GnuPG) 2.4.4', 'archive_sha256': {'cratectl-apt-app': 'a' * 64, 'cratectl-apt-library': 'b' * 64},
               'release_sha256': 'c' * 64, 'index_sha256': {'Packages': 'd' * 64, 'Packages.gz': 'e' * 64}}
        report = {'schema': 1, 'profile': DEBIAN_APT_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in DEBIAN_APT_FILES},
                  'binary_sha256': {'cratectl': 'd' * 64, 'cratectld': 'e' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(DEBIAN_APT_BASE),
                  'debian_apt': apt, 'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-debian-apt-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 36, 'records': 1})
        for patch in ({'architecture': 'amd64'}, {'checks': [item for item in DEBIAN_APT_CHECKS if 'untrusted-signature' not in item]}):
            with self.assertRaisesRegex(EvidenceError, 'debian_apt_report_contract'):
                validate_custom({**report, 'debian_apt': {**apt, **patch}}, candidate, 12, spec, source)

        def suite_source(path):
            return b'--debian-apt --debian-apt-suite' if path == '.github/workflows/debian-apt.yml' else source(path)

        indexes = {f'main/binary-{arch}/{path}': digest for arch in ('amd64', 'arm64') for path, digest in apt['index_sha256'].items()}
        suite = {**apt, 'checks': list(DEBIAN_SUITE_CHECKS), 'index_sha256': indexes,
                 'archive_sha256': {**apt['archive_sha256'], 'cratectl-apt-app-foreign': 'f' * 64}}
        combined = {**report, 'profile': DEBIAN_SUITE_PROFILE, 'debian_apt_suite': suite,
                    'source_sha256': {path: hashlib.sha256(suite_source(path)).hexdigest() for path in DEBIAN_SUITE_FILES}}
        self.assertEqual(validate_custom(combined, candidate, 12, spec, suite_source), {'checks': 55, 'records': 1})
        incomplete = {**suite, 'index_sha256': {k: d for k, d in indexes.items() if 'amd64' in k}}
        with self.assertRaisesRegex(EvidenceError, 'debian_apt_report_contract'):
            validate_custom({**combined, 'debian_apt_suite': incomplete}, candidate, 12, spec, suite_source)
        flat_for_suite = {**report, 'source_sha256': {path: hashlib.sha256(suite_source(path)).hexdigest() for path in DEBIAN_APT_FILES}}
        with self.assertRaisesRegex(EvidenceError, 'debian_apt_profile_selection'):
            validate_custom(flat_for_suite, candidate, 12, spec, suite_source)

    def test_public_nuget_checks_exact_archive_and_lock_domains(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        fixture = {'sdk': '10.0.403', 'version': '8.5.2', 'dotnet_sha256': 'b' * 64,
                   'lock_sha256': 'c' * 64, 'archive_sha256': NUGET_PUBLIC_ARCHIVES, 'lock_content_sha512': NUGET_PUBLIC_CONTENT}
        report = {'schema': 1, 'profile': NUGET_PUBLIC_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'X64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in NUGET_PUBLIC_FILES},
                  'binary_sha256': {'cratectl': 'd' * 64, 'cratectld': 'e' * 64}, 'postgres': 'postgres (PostgreSQL) 16.15',
                  'database_safety': True, 'checks': list(NUGET_PUBLIC_CHECKS), 'nuget_public': fixture,
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-nuget-public-amd64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 22, 'records': 1})
        invalid = {**fixture, 'lock_content_sha512': NUGET_PUBLIC_ARCHIVES}
        with self.assertRaisesRegex(EvidenceError, 'nuget_public_report_contract'):
            validate_custom({**report, 'nuget_public': invalid}, candidate, 12, spec, source)

    def test_nuget_proxy_requires_closed_stock_and_source_inventory(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': NUGET_PROXY_PROFILE, 'candidate': candidate, 'status': 'passed',
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in NUGET_PROXY_FILES},
                  'binary_sha256': {'cratectl': 'c' * 64, 'cratectld': 'd' * 64}, 'postgres': 'postgres (PostgreSQL) 16.15',
                  'database_safety': True, 'checks': list(NUGET_PROXY_CHECKS), 'goal_complete': False, 'broad_readiness': False,
                  'nuget_proxy': {'sdk': '10.0.403', 'dotnet_sha256': 'f' * 64, 'fixtures': NUGET_PROXY_FIXTURES,
                                  'loopback_http': True, 'origin_requests': 6}}
        spec = SPECS['ci-summary-nuget-proxy-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 30, 'records': 1})
        for field, value in [('database_safety', False), ('checks', report['checks'][:-1]),
                             ('nuget_proxy', {**report['nuget_proxy'], 'origin_requests': 7})]:
            with self.subTest(field=field), self.assertRaisesRegex(EvidenceError, 'nuget_proxy_report_contract'):
                validate_custom({**report, field: value}, candidate, 12, spec, source)
        with self.assertRaisesRegex(EvidenceError, 'nuget_proxy_source_identity'):
            validate_custom(report, candidate, 12, spec, lambda path: source(path) + b'changed')

        def combined_source(path):
            return b'--with-groups-and-service-index' if path == '.github/workflows/nuget-proxy.yml' else source(path)

        selected = {path: hashlib.sha256(combined_source(path)).hexdigest() for path in NUGET_COMBINED_FILES}
        combined = {**report, 'profile': NUGET_COMBINED_PROFILE, 'source_sha256': selected,
                    'checks': list(NUGET_COMBINED_CHECKS), 'nuget_group': NUGET_GROUP_FIXTURES,
                    'nuget_service_index': NUGET_SERVICE_INDEX_FIXTURE}
        self.assertEqual(validate_custom(combined, candidate, 12, spec, combined_source), {'checks': 69, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'nuget_proxy_report_contract'):
            validate_custom({**combined, 'nuget_service_index': {**NUGET_SERVICE_INDEX_FIXTURE, 'separate_credentials_verified': 1}},
                            candidate, 12, spec, combined_source)
        with self.assertRaisesRegex(EvidenceError, 'nuget_proxy_profile_selection'):
            validate_custom({**report, 'source_sha256': {path: selected[path] for path in NUGET_PROXY_FILES}},
                            candidate, 12, spec, combined_source)

    def test_maven_index_report_binds_stock_reader_and_exact_source(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        index = {'checks': list(MAVEN_INDEX_CHECKS), 'reader': '7.1.6', 'reader_sha256': INDEXER_SHA256,
                 'java': 'openjdk 21.0.13 2026-10-20 LTS', 'archive_sha256': 'd' * 64, 'jar_sha256': [letter * 64 for letter in 'ef0']}
        report = {'schema': 1, 'profile': MAVEN_INDEX_PROFILE, 'candidate': candidate,
                  'runner_os': 'Linux', 'runner_arch': 'X64', 'run_id': '12', 'status': 'passed', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in MAVEN_INDEX_FILES},
                  'binary_sha256': {'cratectl': 'a' * 64, 'cratectld': 'b' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(MAVEN_INDEX_BASE),
                  'maven_index': index, 'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-maven-index-amd64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 27, 'records': 1})
        for mutation in ({'reader_sha256': '0' * 64}, {'java': 'openjdk 23'}, {'jar_sha256': ['e' * 64] * 3},
                         {'checks': list(MAVEN_INDEX_CHECKS)[1:]}, {'private_log': 'inert fixture output'}):
            with self.subTest(change=mutation.keys()), self.assertRaises(EvidenceError):
                validate_custom({**report, 'maven_index': {**index, **mutation}}, candidate, 12, spec, source)
        with self.assertRaisesRegex(EvidenceError, 'maven_index_source_identity'):
            validate_custom(report, candidate, 12, spec, lambda path: b'changed')

        def cached_source(path):
            if path == '.github/workflows/maven-index.yml':
                return b'--maven-index-cached --maven-index-ci-architecture'
            return source(path)

        def bind(body, paths):
            return {**body, 'source_sha256': {path: hashlib.sha256(cached_source(path)).hexdigest() for path in paths}}

        cached = {'checks': list(MAVEN_CACHED_CHECKS), 'archive_sha256': '1' * 64, 'jar_sha256': index['jar_sha256'][1],
                  'pom_sha256': '2' * 64, 'groups': {'checks': list(MAVEN_GROUP_CHECKS), 'archive_sha256': '3' * 64}}
        combined = bind({**report, 'profile': MAVEN_CACHED_PROFILE, 'maven_index': {**index, 'cached': cached}}, MAVEN_CACHED_FILES)
        self.assertEqual(validate_custom(combined, candidate, 12, spec, cached_source), {'checks': 41, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'maven_index_profile_selection'):
            validate_custom(bind(report, MAVEN_INDEX_FILES), candidate, 12, spec, cached_source)
        with self.assertRaisesRegex(EvidenceError, 'maven_index_report_contract'):
            validate_custom({**combined, 'maven_index': {**index, 'cached': {**cached, 'jar_sha256': '4' * 64}}}, candidate, 12, spec, cached_source)

    def test_oci_catalog_requires_architecture_bound_tool_and_exact_graph_checks(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        catalog = {'oras': '1.3.6', 'oras_sha256': 'd' * 64, 'checks': list(CATALOG_CHECKS),
                   'manifest_sha256': [letter * 64 for letter in 'ef1'], 'payload_sha256': ['2' * 64, '3' * 64]}
        report = {'schema': 1, 'profile': 'cratectl-native-oci-repository-catalog-v1', 'candidate': candidate,
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'status': 'passed', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in OCI_CATALOG_FILES},
                  'binary_sha256': {'cratectl': 'a' * 64, 'cratectld': 'b' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(OCI_CATALOG_BASE),
                  'oci_repository_catalog': catalog, 'oras_archive_sha256': ORAS_PINS['ARM64'],
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-oci-catalog-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 28, 'records': 1})
        for mutation in ({'oras_archive_sha256': ORAS_PINS['X64']},
                         {'oci_repository_catalog': {**catalog, 'checks': list(CATALOG_CHECKS)[:-1]}},
                         {'oci_repository_catalog': {**catalog, 'payload_sha256': ['2' * 64] * 2}},
                         {'oci_repository_catalog': {**catalog, 'private_log': 'discarded fixture metadata'}}):
            with self.subTest(change=mutation.keys()), self.assertRaises(EvidenceError):
                validate_custom({**report, **mutation}, candidate, 12, spec, source)
        with self.assertRaisesRegex(EvidenceError, 'oci_catalog_source_identity'):
            validate_custom(report, candidate, 12, spec, lambda path: b'different')

        def cached_source(path):
            if path == '.github/workflows/oci-repository-catalog.yml':
                return b'--oci-catalog-cached --oci-catalog-ci-architecture'
            return source(path)

        cached = {'checks': list(OCI_CACHED_CHECKS), 'manifest_sha256': catalog['manifest_sha256'][0],
                  'payload_sha256': catalog['payload_sha256'][0], 'groups': {
                      'checks': list(GROUP_CHECKS), 'lower_manifest_sha256': '6' * 64,
                      'lower_payload_sha256': catalog['payload_sha256'][0]}}

        def bind(report, paths):
            return {**report, 'source_sha256': {path: hashlib.sha256(cached_source(path)).hexdigest() for path in paths}}

        combined = bind({**report, 'profile': OCI_CACHED_PROFILE, 'oci_repository_catalog': {**catalog, 'cached': cached}}, OCI_CACHED_FILES)
        self.assertEqual(validate_custom(combined, candidate, 12, spec, cached_source), {'checks': 42, 'records': 1})
        with self.assertRaisesRegex(EvidenceError, 'oci_catalog_profile_selection'):
            validate_custom(bind(report, OCI_CATALOG_FILES), candidate, 12, spec, cached_source)
        incomplete = {**cached, 'groups': {**cached['groups'], 'checks': list(GROUP_CHECKS)[:-1]}}
        with self.assertRaisesRegex(EvidenceError, 'oci_catalog_report_contract'):
            validate_custom({**combined, 'oci_repository_catalog': {**catalog, 'cached': incomplete}}, candidate, 12, spec, cached_source)

    def test_python_search_report_binds_exact_pip_and_twine_and_cached_scope(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': 'cratectl-native-python-search-v1', 'candidate': candidate,
                  'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '12', 'status': 'passed', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in PYTHON_FILES},
                  'binary_sha256': {'cratectl': 'a' * 64, 'cratectld': 'b' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(PYTHON_BASE),
                  'python_search': {'checks': list(PYTHON_HOSTED), 'archive_sha256': [letter * 64 for letter in 'def'],
                                    'pip': '26.1.2', 'twine': '7.0.0'},
                  'python_cached_search': {'checks': list(PYTHON_CACHED), 'preferred_archive_sha256': '1' * 64},
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-python-search-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 37, 'records': 1})
        for scope, override in (
                ('python_search', {'pip': '26.0.1'}), ('python_search', {'twine': '6.2.0'}),
                ('python_cached_search', {'checks': list(PYTHON_CACHED)[:-1]}),
                ('python_cached_search', {'preferred_archive_sha256': 'd' * 64}),
                ('python_cached_search', {'private_output': 'inert stand-in'})):
            with self.subTest(scope=scope, change=list(override)), self.assertRaises(EvidenceError):
                validate_custom({**report, scope: {**report[scope], **override}}, candidate, 12, spec, source)
        with self.assertRaisesRegex(EvidenceError, 'python_search_source_identity'):
            validate_custom(report, candidate, 12, spec, lambda path: b'changed')

    def test_npm_search_report_binds_both_scopes_and_exact_sources(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': 'cratectl-native-npm-search-v1', 'candidate': candidate,
                  'runner_os': 'Linux', 'runner_arch': 'X64', 'run_id': '12', 'status': 'passed', 'source_dirty': False,
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in NPM_FILES},
                  'binary_sha256': {'cratectl': 'a' * 64, 'cratectld': 'b' * 64}, 'archive_sha256': 'c' * 64,
                  'postgres': 'postgres (PostgreSQL) 16.15', 'npm': '10.9.9', 'checks': list(NPM_BASE),
                  'npm_search': {'checks': list(NPM_HOSTED), 'archive_sha256': [letter * 64 for letter in 'def0']},
                  'npm_cached_search': {'checks': list(NPM_CACHED), 'preferred_archive_sha256': '1' * 64},
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-npm-search-amd64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 37, 'records': 1})
        for changed in ({'npm_search': {'checks': [], 'archive_sha256': report['npm_search']['archive_sha256']}},
                        {'npm_cached_search': {'checks': list(NPM_CACHED), 'preferred_archive_sha256': 'd' * 64}},
                        {'npm_cached_search': {**report['npm_cached_search'], 'private_output': 'owned stand-in'}},
                        {'runner_arch': 'ARM64'}, {'source_sha256': dict.fromkeys(NPM_FILES, 'd' * 64)}):
            with self.subTest(change=list(changed)), self.assertRaises(EvidenceError):
                validate_custom({**report, **changed}, candidate, 12, spec, source)

    def test_oci_check_inventory_tracks_the_selected_source_fixture(self):
        class Source:
            path = 'scripts/conformance_oci_clients.py'
            paths = {path}

            def __init__(self, content):
                self.content = content

            def __call__(self, path):
                assert path == self.path
                return self.content

        old = Source(b'helm_login()')
        new = Source((ROOT / Source.path).read_bytes())
        spec = SPECS['ci-summary-oci-clients-amd64']
        for candidate, source, wrong, checks in [('ab6e559', old, new, 214), ('ee1e955', new, old, 219)]:
            report = json.loads((ROOT / 'evidence/2026-11-19' / ('github-' + candidate) /
                                 'ci-summary-oci-clients-amd64.json').read_text())
            with self.subTest(candidate=candidate):
                validate_summary(report, report['candidate'], int(report['run_id']), spec, [], source)
                self.assertEqual(report['records'][0]['checks'], checks)
                with self.assertRaisesRegex(EvidenceError, 'oci_report_inventory'):
                    validate_summary(report, report['candidate'], int(report['run_id']), spec, [], wrong)

    def test_offline_media_binds_both_phases_source_archive_and_image_inventory(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': 'cratectl-native-offline-media-v1', 'candidate': candidate, 'run_id': '12',
                  'runner_os': 'Linux', 'runner_arch': 'X64', 'status': 'passed', 'source_dirty': False,
                  'checks': list(OFFLINE_CHECKS), 'runtime_phases': [
                      {'phase': name, 'checks': list(checks), 'artifact_digest': 'b' * 64, 'npm': '10.9.9'}
                      for name, checks in OFFLINE_PHASES.items()],
                  'archive_sha256': 'c' * 64, 'manifest_sha256': 'd' * 64,
                  'image_configuration_sha256': {'postgres': 'sha256:' + 'e' * 64, 'registry': 'sha256:' + 'f' * 64},
                  'source_sha256': {name: hashlib.sha256(source(name)).hexdigest() for name in OFFLINE_FILES},
                  'goal_complete': False, 'broad_readiness': False, 'database_schema': 19, 'forced_tenant_tables': 59}
        spec = SPECS['ci-summary-offline-media-amd64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 27, 'records': 1})
        for changed in ({'checks': report['checks'][:-1]}, {'runner_arch': 'ARM64'}, {'forced_tenant_tables': 59.0},
                        {'runtime_phases': report['runtime_phases'][:1]}, {'profile': 'unknown'}, {'token': 'inert test'}):
            with self.subTest(change=list(changed)), self.assertRaises(EvidenceError):
                validate_custom({**report, **changed}, candidate, 12, spec, source)
        for field, key in [('source_sha256', 'scripts/linux_offline_media.py'), ('runtime_phases', 1)]:
            altered = copy.deepcopy(report)
            if key == 1:
                altered[field][key]['artifact_digest'] = 'c' * 64
            else:
                altered[field][key] = 'a' * 64
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                validate_custom(altered, candidate, 12, spec, source)

    def test_linux_install_requires_exact_safe_native_result(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': 'cratectl-native-linux-install-v1', 'candidate': candidate,
                  'run_id': '12', 'runner_os': 'Linux', 'runner_arch': 'ARM64', 'status': 'passed',
                  'source_dirty': False, 'checks': list(INSTALL_CHECKS), 'python_image': INSTALL_IMAGE,
                  'archive_sha256': '0' * 64, 'binary_sha256': {'cratectl': '1' * 64, 'cratectld': '2' * 64},
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in INSTALL_FILES},
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-linux-install-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 12, 'records': 1})
        for altered in ({'checks': report['checks'][:-1]}, {'runner_arch': 'X64'}, {'run_id': None},
                        {'python_image': INSTALL_IMAGE.split('@')[0]}, {'archive_sha256': 'x' * 64},
                        {'broad_readiness': True}, {'private_path': '/private/fixture'}):
            with self.subTest(altered=altered), self.assertRaises(EvidenceError):
                validate_custom({**report, **altered}, candidate, 12, spec, source)
        altered = copy.deepcopy(report)
        altered['source_sha256']['scripts/install_linux_candidate.py'] = '9' * 64
        with self.assertRaisesRegex(EvidenceError, 'linux_install_source_identity'):
            validate_custom(altered, candidate, 12, spec, source)

    def test_compose_requires_complete_private_free_exact_source_report(self):
        source = lambda path: path.encode()
        candidate = 'a' * 40
        report = {'schema': 1, 'profile': 'cratectl-compose-evaluation-v1', 'candidate': candidate,
                  'run_id': '12', 'runner_os': 'Linux', 'runner_arch': 'ARM64', 'status': 'passed',
                  'source_dirty': False, 'checks': list(COMPOSE_CHECKS), 'compose_version': 'v5.7.0',
                  'npm_version': '11.16.0', 'go_version': '1.27.4', 'database_schema': 19,
                  'forced_rls_tenant_tables': 59, 'runtime_image_id': 'sha256:' + '0' * 64,
                  'binary_sha256': {'cratectl': '1' * 64, 'cratectld': '2' * 64},
                  'source_sha256': {path: hashlib.sha256(source(path)).hexdigest() for path in COMPOSE_FILES},
                  'goal_complete': False, 'broad_readiness': False}
        spec = SPECS['ci-summary-compose-arm64']
        self.assertEqual(validate_custom(report, candidate, 12, spec, source), {'checks': 20, 'records': 1})
        for changed in ({'checks': report['checks'][:-1]}, {'source_dirty': True},
                        {'runner_arch': 'X64'}, {'owner_password': 'owned inert stand-in'},
                        {'broad_readiness': True}, {'forced_rls_tenant_tables': 0}):
            with self.subTest(changed=list(changed)), self.assertRaises(EvidenceError):
                validate_custom({**report, **changed}, candidate, 12, spec, source)
        altered = copy.deepcopy(report)
        altered['source_sha256']['deploy/compose/Dockerfile'] = '9' * 64
        with self.assertRaisesRegex(EvidenceError, 'compose_source_identity'):
            validate_custom(altered, candidate, 12, spec, source)

    def requirement_pair(self, role):
        summary, source = self.common_pair(role)
        code_hash = hashlib.sha256(source('owned')).hexdigest()
        requirement = copy.deepcopy(summary['records'][1])
        del requirement['go_common_export_portability_contract']
        contract = complete_requirement_contract(role)
        contract['source_run_id'] = str(summary['run_id'])
        for key in ['script_sha256', 'fixture_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256',
                    'native_helper_sha256', 'probe_helper_sha256', 'process_helper_sha256', 'decoder_sha256', 'reader_source_sha256']:
            contract[key] = code_hash
        requirement.update(report='owned-requirement-portability.json', raw_report_sha256='f' * 64,
                           checks=4 if role == 'producer' else 14, go_requirement_export_portability_contract=contract)
        summary['records'].append(requirement)
        source.paths = set(source.paths) | {'scripts/conformance_go_requirement_export_portable.py'}
        return summary, source

    def test_requirement_profile_keeps_all_three_separate_source_bound_reports(self):
        for role in ['producer', 'consumer']:
            summary, source = self.requirement_pair(role)
            spec = SPECS['ci-summary-export-portability-' + role]
            counts, contracts = validate_summary(summary, summary['candidate'], int(summary['run_id']), spec, self.baselines, source)
            self.assertEqual(counts['records'], 3)
            self.assertEqual(len(contracts), 3)
            self.assertEqual(counts['checks'], 11 if role == 'producer' else 41)
            for index in range(3):
                changed = copy.deepcopy(summary)
                del changed['records'][index]
                with self.subTest(role=role, missing=index), self.assertRaisesRegex(EvidenceError, 'requirement_profile_report_inventory'):
                    validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)

    def test_requirement_profile_binds_each_source_dependency_and_rejects_collapsed_record(self):
        summary, source = self.requirement_pair('producer')
        spec = SPECS['ci-summary-export-portability-producer']
        for key in ['probe_helper_sha256', 'reader_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256']:
            changed = copy.deepcopy(summary)
            changed['records'][2]['go_requirement_export_portability_contract'][key] = '0' * 64
            with self.subTest(key=key), self.assertRaisesRegex(EvidenceError, 'requirement_portable_source_identity'):
                validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)
        changed = copy.deepcopy(summary)
        changed['records'][1]['go_requirement_export_portability_contract'] = changed['records'][2].pop('go_requirement_export_portability_contract')
        with self.assertRaisesRegex(EvidenceError, 'requirement_profile_report_inventory'):
            validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)

    def common_pair(self, role='producer'):
        summary = self.report('ci-summary-export-portability-' + role)
        code = b'owned frozen source data, never executed'
        code_hash = hashlib.sha256(code).hexdigest()
        old = summary['records'][0]
        old['go_export_portability_contract']['script_sha256'] = code_hash
        old['go_export_portability_contract']['fixture_source_sha256'] = code_hash
        common = copy.deepcopy(old)
        del common['go_export_portability_contract']
        contract = complete_common_contract(role)
        contract['source_run_id'] = str(summary['run_id'])
        for key in ['script_sha256', 'fixture_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256',
                    'native_helper_sha256', 'process_helper_sha256', 'decoder_sha256']:
            contract[key] = code_hash
        common.update(report='owned-common-portability.json', raw_report_sha256='e' * 64,
                      checks=4 if role == 'producer' else 14, go_common_export_portability_contract=contract)
        summary['records'].append(common)

        class FrozenSource:
            paths = {'scripts/conformance_go_common_export_portable.py'}

            def __call__(self, _):
                return code

        return summary, FrozenSource()

    def test_current_portability_requires_both_original_and_common_source_bound_records(self):
        for role in ['producer', 'consumer']:
            summary, source = self.common_pair(role)
            name = 'ci-summary-export-portability-' + role
            counts, contracts = validate_summary(summary, summary['candidate'], int(summary['run_id']), SPECS[name], self.baselines, source)
            self.assertEqual(counts['records'], 2)
            self.assertEqual(len(contracts), 2)
            for index in range(2):
                changed = copy.deepcopy(summary)
                del changed['records'][index]
                with self.subTest(role=role, missing=index), self.assertRaisesRegex(EvidenceError, 'common_profile_report_inventory'):
                    validate_summary(changed, changed['candidate'], int(changed['run_id']), SPECS[name], self.baselines, source)

    def test_common_code_identity_and_separate_record_cannot_be_substituted(self):
        summary, source = self.common_pair()
        name = 'ci-summary-export-portability-producer'
        bad = copy.deepcopy(summary)
        bad['records'][1]['go_common_export_portability_contract']['process_helper_sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'common_portable_source_identity'):
            validate_summary(bad, bad['candidate'], int(bad['run_id']), SPECS[name], self.baselines, source)
        bad = copy.deepcopy(summary)
        bad['records'][0]['go_common_export_portability_contract'] = bad['records'][1].pop('go_common_export_portability_contract')
        with self.assertRaisesRegex(EvidenceError, 'common_profile_report_inventory'):
            validate_summary(bad, bad['candidate'], int(bad['run_id']), SPECS[name], self.baselines, source)

    def setUp(self):
        self.baselines = json.loads((ROOT / 'scripts/ci/testdata/schema16-historical-baselines.json').read_text())['baselines']

    def report(self, name):
        report = json.loads((ROOT / 'evidence/2026-11-07/github-4956197' / (name + '.json')).read_text())
        for record in report['records']:
            if 'go_export_portability_contract' in record:
                # Exercise today's validator using the archived report shape.
                # These in-memory fixtures are not campaign evidence.
                record['go_export_portability_contract']['go_version'] = '1.27.4'
        return report

    def validate(self, name, report):
        return validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines)

    def test_every_retained_report_shape_is_understood_with_the_current_sdk(self):
        paths = list((ROOT / 'evidence/2026-11-07/github-4956197').glob('*.json'))
        self.assertEqual(len(paths), 19)
        records = 0
        for path in paths:
            with self.subTest(profile=path.stem):
                report = self.report(path.stem)
                summary, _ = self.validate(path.stem, report)
                records += summary['records']
                self.assertNotIn('candidate', summary)
        self.assertEqual(records, 72)

    def test_archived_portability_result_does_not_qualify_current_sdk(self):
        name = 'ci-summary-export-portability-consumer'
        path = ROOT / 'evidence/2026-11-07/github-4956197' / (name + '.json')
        original = json.loads(path.read_text())
        with self.assertRaisesRegex(EvidenceError, 'typed_report_contract'):
            self.validate(name, original)

    def test_new_schema17_contract_refuses_old15_baseline_campaign(self):
        current = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_text())['baselines'][:-2]
        self.assertEqual({row['schema'] for row in current}, {None, *range(2, 17)})
        original = self.report('ci-summary-upgrades-amd64')
        with self.assertRaisesRegex(EvidenceError, 'historical_baselines'):
            validate_summary(original, original['candidate'], int(original['run_id']), SPECS['ci-summary-upgrades-amd64'], current)

    def test_schema18_requires_actual17_historical_binary_and_upgrade_report(self):
        current = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_text())['baselines'][:-1]
        self.assertEqual([row['schema'] for row in current], [None, *range(2, 18)])
        original = json.loads((ROOT / 'evidence/2026-11-07/github-bb6f728/ci-summary-upgrades-amd64.json').read_bytes())
        with self.assertRaisesRegex(EvidenceError, 'historical_baselines'):
            validate_summary(original, original['candidate'], int(original['run_id']), SPECS['ci-summary-upgrades-amd64'], current)

    def test_metadata_empty_partial_and_unreviewed_record_never_pass(self):
        original = self.report('ci-summary-go-module-amd64')
        for kind in ['source', 'platform', 'empty', 'unknown', 'no-counts', 'dirty', 'binary', 'partial-contract', 'checks']:
            with self.subTest(kind=kind):
                report = copy.deepcopy(original)
                record = report['records'][0]
                if kind == 'source':
                    report['candidate'] = '0' * 40
                elif kind == 'platform':
                    report['runner_arch'] = 'ARM64'
                elif kind == 'empty':
                    report['records'] = []
                elif kind == 'unknown':
                    record['private_context'] = 'private-synthetic'
                elif kind == 'no-counts':
                    record['checks'] = record['cases'] = None
                elif kind == 'dirty':
                    record['source_dirty'] = True
                elif kind == 'binary':
                    record['artifacts'][0]['build']['vcs.modified'] = 'true'
                elif kind == 'partial-contract':
                    record['go_module_contract']['completed'].pop()
                elif kind == 'checks':
                    record['checks'] -= 1
                with self.assertRaises(EvidenceError):
                    validate_summary(report, original['candidate'], int(original['run_id']), SPECS['ci-summary-go-module-amd64'], self.baselines)

    def test_runtime_reports_require_both_candidate_binaries_and_one_identity_per_job(self):
        for name in ['ci-summary-go-module-amd64', 'ci-summary-amd64', 'ci-summary-export-portability-consumer', 'ci-summary-upgrades-amd64']:
            original = self.report(name)
            index = next(n for n, r in enumerate(original['records']) if r.get('artifacts'))
            for mutation in ['missing', 'empty', 'one']:
                report = copy.deepcopy(original)
                record = report['records'][index]
                if mutation == 'missing':
                    record.pop('artifacts')
                    record['source_dirty'] = record['build_source_matches_candidate'] = None
                elif mutation == 'empty':
                    record['artifacts'] = []
                else:
                    record['artifacts'] = [a for a in record['artifacts'] if a['path'] != '.cache/ci-build/cratectl']
                with self.subTest(profile=name, mutation=mutation), self.assertRaises(EvidenceError):
                    self.validate(name, report)
        report = self.report('ci-summary-amd64')
        report['records'][-1]['artifacts'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'candidate_binary_identity_changed'):
            self.validate('ci-summary-amd64', report)

    def test_historical_browser_and_native_report_inventories_are_complete(self):
        pinned = {row['binary'] for row in self.baselines}
        for name, mutation in [
            ('ci-summary-amd64', lambda r: r['records'].pop()),
            ('ci-summary-amd64', lambda r: next(x for x in r['records'] if 'browser' in x)['browser'].update(skipped=1)),
            ('ci-summary-upgrades-amd64', lambda r: next(x for x in r['records'] if 'baselines' in x)['baselines'].pop()),
            ('ci-summary-upgrades-amd64', lambda r: next(x for x in r['records'] if x.get('baseline_version') == 15).update(checks=95)),
            ('ci-summary-upgrades-amd64', lambda r: next(a for x in r['records'] if x.get('baseline_version') == 15 for a in x['artifacts'] if a['path'] in pinned).update(sha256='0' * 64)),
            ('ci-summary-export-portability-consumer', lambda r: r['records'][0]['go_export_portability_contract'].update(network_isolated=False)),
        ]:
            with self.subTest(name=name):
                report = self.report(name)
                mutation(report)
                with self.assertRaises(EvidenceError):
                    self.validate(name, report)

    def test_source_fixture_identity_is_checked_separately_from_internal_hash_maps(self):
        report = self.report('ci-summary-go-module-amd64')
        name = 'ci-summary-go-module-amd64'
        source = lambda _: (ROOT / 'scripts/conformance_go.py').read_bytes()
        report['records'][0]['go_module_contract']['fixture_source_sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'go_fixture_source_identity'):
            validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)
        report['records'][0]['go_module_contract']['fixture_source_sha256'] = hashlib.sha256(source('')).hexdigest()
        validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)
        contract = report['records'][0]['go_module_contract']
        old = contract['publisher_sha256']['application_1_mod']
        for key in ['publisher_sha256', 'reference_sha256', 'wire_sha256', 'cached_sha256']:
            contract[key] = {k: ('f' * 64 if value == old else value) for k, value in contract[key].items()}
        with self.assertRaisesRegex(EvidenceError, 'go_publisher_fixture_identity'):
            validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)

    def test_custom_library_and_strict_controls_require_complete_clean_results(self):
        path = ROOT / 'evidence/2026-11-07/github-fbe3bf9-final/ci-summary-nuget-version-arm64.json'
        library = json.loads(path.read_text())
        spec = SPECS['ci-summary-nuget-version-arm64']
        self.assertEqual(validate_custom(library, library['candidate'], int(library['run_id']), spec, lambda _: b''), {'checks': 37, 'records': 1})
        library['mismatch_indexes'] = [1]
        with self.assertRaises(EvidenceError):
            validate_custom(library, library['candidate'], int(library['run_id']), spec, lambda _: b'')
        controls = ['verified-cold', 'verified-warm', 'fresh-consumer', 'zip-mismatch', 'mod-mismatch', 'invalid-signature', 'authority-unavailable']
        source = lambda _: b'owned-public-fixture'
        strict = {'schema': 1, 'candidate': 'a' * 40, 'run_id': '1', 'runner_os': 'Linux', 'runner_arch': 'x86_64',
                  'status': 'passed', 'source_dirty': False, 'required_controls': controls,
                  'controls': dict.fromkeys(controls, 'passed'), 'go_version': '1.27.4', 'go_binary_sha256': 'b' * 64,
                  'script_sha256': hashlib.sha256(source('')).hexdigest(), 'fixture_sha256': hashlib.sha256(source('')).hexdigest(),
                  'zip_rejected_first': True, 'untrusted_zip_sum_retained': False,
                  'retry_succeeded': False, 'altered_inert_file_extracted': False}
        spec = SPECS['ci-summary-checksum-client-linux-amd64']
        self.assertEqual(validate_custom(strict, 'a' * 40, 1, spec, source), {'checks': 7, 'records': 1})
        for mutation in [lambda r: r['controls'].pop('zip-mismatch'), lambda r: r.update(status='failed'),
                         lambda r: r.update(go_version='1.27.3'),
                         lambda r: r.update(retry_succeeded=True), lambda r: r.update(altered_inert_file_extracted=True)]:
            report = copy.deepcopy(strict)
            mutation(report)
            with self.assertRaises(EvidenceError):
                validate_custom(report, 'a' * 40, 1, spec, source)


if __name__ == '__main__':
    unittest.main()
