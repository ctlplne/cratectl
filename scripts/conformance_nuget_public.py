# SPDX-License-Identifier: BUSL-1.1
"""Restore one pinned public dependency graph with stock dotnet and cratectl."""

import base64
import hashlib
import io
import json
from pathlib import Path
import shutil
import urllib.request
import uuid
import zipfile

from bounded_client import run_owned_client
from conformance_nuget_proxy import stock_environment, stock_feed_config
from qualification_contract import dotnet_sdk_pin

SERVICE = 'https://api.nuget.org/v3/index.json'
PACKAGE_BASE = 'https://api.nuget.org/v3-flatcontainer/'
VERSION = '8.5.2'
PACKAGES = {'Polly': '22b374e9d74e209d1562e55e7dedcbbdf5b4917db4013450904060f420689910',
            'Polly.Core': '3c0c2c5aaac289e09fffb63cedf57b5cc2a8698d9a6c240db48fb8a32c8c89f9'}
MAX_PACKAGE = 2 << 20


class DirectFixture(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def package_path(name):
    key = name.lower()
    return f'{key}/{VERSION}/{key}.{VERSION}.nupkg'


def exact_public_bytes():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), DirectFixture())
    packages = {}
    for name, expected in PACKAGES.items():
        address = PACKAGE_BASE + package_path(name)
        with opener.open(address, timeout=15) as response:
            raw = response.read(MAX_PACKAGE + 1)
            if len(raw) > MAX_PACKAGE or response.status != 200 or response.url != address:
                raise ValueError('the pinned public NuGet response exceeded its reviewed scope')
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('the public NuGet fixture digest changed')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            unsafe = {'build', 'buildmultitargeting', 'buildtransitive', 'tools', 'analyzers', 'contentfiles'}
            entries = archive.namelist()
            if len(entries) > 100 or any(path.lower().split('/')[0] in unsafe or
                    path.lower().endswith(('.props', '.targets', '.ps1', '.sh', '.bat', '.cmd', '.exe')) for path in entries):
                raise ValueError('public restore fixtures must contain no build assets or package scripts')
        packages[name] = raw
    return packages


def public_nuget(h):
    scope = h.PRIVATE / 'cratectl-nuget-public'
    scope.mkdir(mode=0o700)
    dotnet = shutil.which('dotnet')
    h.check('stock dotnet is available for public origin qualification', dotnet is not None)
    env = stock_environment(scope)
    code, version = run_owned_client([dotnet, '--version'], h.ROOT, env, timeout=15)
    h.check('public origin replay uses the exact pinned dotnet SDK', code == 0 and version.strip() == dotnet_sdk_pin(h.ROOT))
    with Path(dotnet).resolve().open('rb') as binary:
        dotnet_sha256 = hashlib.file_digest(binary, 'sha256').hexdigest()
    packages = exact_public_bytes()
    h.check('both direct public package ZIPs match their independent SHA-256 pins and contain no build assets or scripts', set(packages) == set(PACKAGES))
    source = scope / 'vendor-fixture'
    source.mkdir(mode=0o700)
    for name, raw in packages.items():
        (source / (name.lower() + '.' + VERSION + '.nupkg')).write_bytes(raw)
    baseline_config = stock_feed_config(scope / 'vendor.config', str(source))
    checkpoint = {}

    def consume(label, config, *, lock=None, denied=False):
        work = scope / label
        work.mkdir(mode=0o700)
        project = work / 'Owned.csproj'
        project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>'
                           '<NuGetAudit>false</NuGetAudit><EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
                           '</PropertyGroup><ItemGroup><PackageReference Include="Polly" Version="[8.5.2]" '
                           'ExcludeAssets="build;buildTransitive;buildMultitargeting;analyzers;contentFiles" /></ItemGroup></Project>')
        expected_lock = work / 'packages.lock.json'
        if lock is not None:
            expected_lock.write_bytes(lock)
        installed = work / 'cache'
        extra = dict(env, NUGET_PACKAGES=str(installed), NUGET_HTTP_CACHE_PATH=str(work / 'http'),
                     NUGET_PLUGINS_CACHE_PATH=str(work / 'plugins'))
        args = [dotnet, 'restore', project, '--configfile', config, '--packages', installed, '--no-http-cache',
                '--force', '--verbosity', 'minimal', '--locked-mode' if lock is not None else '--use-lock-file']
        with (work / 'restore.log').open('xb') as log:
            code, output = run_owned_client(args, work, extra, timeout=75, capture_limit=32 << 10, output_sink=log)
        if denied:
            h.check('a fresh locked restore respects public proxy review revocation',
                    code != 0 and ('NU1101' in output or 'NU1301' in output or '403 (Forbidden)' in output))
            return None
        h.check('stock dotnet restores the pinned public package graph ' + label, code == 0)
        lock_bytes = expected_lock.read_bytes()
        dependencies = json.loads(lock_bytes)['dependencies']['net10.0']
        h.check('the stock lock binds Polly and its actual Polly.Core dependency ' + label,
                set(dependencies) == set(PACKAGES) and dependencies['Polly']['type'] == 'Direct' and
                dependencies['Polly.Core']['type'] == 'Transitive' and 'Polly.Core' in dependencies['Polly']['dependencies'] and
                all(item['resolved'] == VERSION for item in dependencies.values()) and (lock is None or lock == lock_bytes))
        for name, raw in packages.items():
            cache_file = installed / package_path(name)
            sha_file = cache_file.with_name(cache_file.name + '.sha512')
            # The stock client's lock and installation hash use NuGet's signed
            # package content definition. The ZIP digest remains independent.
            h.check('restored archive bytes and stock content hash match ' + name + ' ' + label,
                    cache_file.read_bytes() == raw and sha_file.read_text().strip() == dependencies[name]['contentHash'])
            if lock is None:
                checkpoint[name] = base64.b64decode(dependencies[name]['contentHash'], validate=True).hex()
        return lock_bytes

    baseline = consume('independent-vendor-bytes', baseline_config)
    repo = 'cratectl-nuget-public'
    flat = f'/nuget/{repo}/flat/'
    management = f'/api/v1/repositories/{repo}'
    public_networks = ['0.0.0.0/0', '::/0']
    h.repository(repo, 'nuget', review=True, mode='proxy', settings={
        'nuget_service_index': True, 'upstream': {'url': SERVICE, 'networks': public_networks},
        'download_sources': [{'url': PACKAGE_BASE, 'networks': public_networks}], 'cache': {'fresh_seconds': 600}})

    def decision(name, choice):
        key = name.lower()
        return h.req(management + '/decisions', method='PUT', key=uuid.uuid4().hex,
                     data={'path': f'nuget-packages/{key}/{VERSION}.nupkg', 'digest': PACKAGES[name], 'decision': choice})[0]

    for name in PACKAGES:
        h.check('public origin archive stages behind exact digest review ' + name,
                h.req(flat + package_path(name), 'reader')[0] == 403 and decision(name, 'allowed') == 200)
    config = stock_feed_config(scope / 'proxy.config', h.BASE + f'/nuget/{repo}/index.json', h.tokens['reader'])
    consume('public-origin-through-cratectl', config, lock=baseline)
    h.stop()
    h.start()
    consume('warm-public-origin-restart', config, lock=baseline)
    h.check('the current exact public package decision can be revoked', decision('Polly', 'denied') == 200 and
            h.req(flat + package_path('Polly'), 'reader')[0] == 403)
    consume('public-origin-denied', config, lock=baseline, denied=True)
    h.result['nuget_public'] = {'sdk': version.strip(), 'dotnet_sha256': dotnet_sha256, 'version': VERSION,
                                'lock_sha256': hashlib.sha256(baseline).hexdigest(), 'archive_sha256': PACKAGES,
                                'lock_content_sha512': checkpoint}
