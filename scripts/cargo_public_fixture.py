#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check a pinned public Cargo dependency graph through an owned registry."""
import ipaddress
import json
import socket
import ssl
import tomllib
import urllib.error
import urllib.request

from cargo_hosted_fixture import cargo_home, new_project, stock_cargo_environment
from ci.cargo_public_evidence import DOWNLOAD, INDEX, PACKAGES


REPOSITORY = 'cratectl-public-cargo'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def exact_public_networks(host):
    addresses = {ipaddress.ip_address(result[4][0])
                 for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not addresses or len(addresses) > 64 or any(not addr.is_global for addr in addresses):
        raise ValueError(f'public Cargo fixture received unsupported addresses for {host}')
    return [f'{address}/{address.max_prefixlen}' for address in sorted(addresses, key=str)]


def evaluate_public_origin(work, installation, authority, toolchain, environment, call, api, restart, sha):
    checks = []

    def check(name, passed):
        if not passed:
            raise ValueError(name)
        checks.append(name)

    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def read(opener, url, maximum, headers=None):
        with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=15) as response:
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise ValueError('public Cargo fixture response exceeds its byte budget')
            return body

    index_config = json.loads(read(direct, INDEX + '/config.json', 16 << 10))
    check('the public sparse index advertises the configured crates.io CDN',
          index_config['dl'] == DOWNLOAD and not index_config.get('auth-required'))
    records = {}
    for name, (version, digest) in PACKAGES.items():
        path = f'/{name[:2]}/{name[2:4]}/{name}'
        entry, = [row for line in read(direct, INDEX + path, 512 << 10).splitlines()
                  if (row := json.loads(line))['vers'] == version]
        check(f'the official index retains the pinned {name} checksum', entry['cksum'] == digest and not entry['yanked'])
        records[name] = entry
    check('the pinned root declares the leaf as a required runtime dependency',
          any(dep['name'] == 'percent-encoding' and not dep['optional'] and dep['kind'] == 'normal'
              for dep in records['form_urlencoded']['deps']))

    management = '/api/v1/repositories/' + REPOSITORY
    settings = {
        'upstream': {'url': INDEX, 'networks': exact_public_networks('index.crates.io')},
        'download_sources': [{'url': DOWNLOAD, 'networks': exact_public_networks('static.crates.io')}],
        'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'stale_seconds': 0},
    }
    api('cargo-public-create', '/api/v1/repositories', 'POST',
        {'name': REPOSITORY, 'format': 'cargo', 'mode': 'proxy', 'access': 'restricted', 'settings': settings})
    grant = {'actor': 'cratectl-reader', 'read': True, 'write': False}
    api('cargo-public-grant', management + '/grants', 'PUT', grant)
    reader = (work / 'reader.token').read_text().strip()
    root = f'{authority}/cargo/{REPOSITORY}'
    project = work / 'cargo-public-client'
    new_project(project, 'cratectl-public-client',
                dependency='\n[dependencies]\nform_urlencoded = { version = "=1.2.1", registry = "cratectl" }\n')
    env = stock_cargo_environment(installation, toolchain / 'rustc', environment)
    cargo = toolchain / 'cargo'

    def lock_graph(label, directory, child):
        call('cargo-public-resolve-' + label, cargo, 'generate-lockfile', cwd=directory, environment=child, timeout=60)
        call('cargo-public-pin-leaf-' + label, cargo, 'update', '-p', 'percent-encoding', '--precise', PACKAGES['percent-encoding'][0],
             cwd=directory, environment=child, timeout=60)

    def fetch(label, directory=project, resolve=False, replace=False):
        home, child = cargo_home(work, 'cargo-public-home-' + label, 'sparse+' + root + '/index/', env, reader)
        if replace:
            with (home / 'config.toml').open('a') as stream:
                stream.write('\n[source.crates-io]\nreplace-with = "cratectl"\n')
        if resolve:
            lock_graph(label, directory, child)
        call('cargo-public-fetch-' + label, cargo, 'fetch', '--locked', cwd=directory, environment=child, timeout=60)
        archives = list(home.glob('registry/cache/*/*.crate'))
        return {archive.name: sha(archive) for archive in archives}

    expected = {f'{name}-{version}.crate': checksum for name, (version, checksum) in PACKAGES.items()}
    check('stock Cargo fetched exactly the pinned public root and leaf archives', fetch('initial', resolve=True) == expected)
    lock = project / 'Cargo.lock'
    with lock.open('rb') as stream:
        lock_data = tomllib.load(stream)
    root_record, = [entry for entry in lock_data['package'] if entry['name'] == 'form_urlencoded']
    leaf_record, = [entry for entry in lock_data['package'] if entry['name'] == 'percent-encoding']
    check('the stock lockfile records the real dependency edge and both public checksums',
          root_record['dependencies'] == ['percent-encoding']
          and all((entry['version'], entry['checksum']) == PACKAGES[entry['name']] for entry in (root_record, leaf_record)))

    restart()
    check('fresh stock Cargo replays the same pinned graph after restart', fetch('restart') == expected)

    canonical = work / 'cargo-public-canonical'
    new_project(canonical, 'cratectl-canonical-client', dependency='\n[dependencies]\nform_urlencoded = "=1.2.1"\n')
    official_home = work / 'cargo-public-canonical-home'
    official_home.mkdir(mode=0o700)
    official_env = {key: value for key, value in env.items() if key not in ('CARGO_HTTP_CAINFO', 'CARGO_HTTP_PROXY')}
    official_env.update(CARGO_HOME=str(official_home), CARGO_REGISTRIES_CRATES_IO_PROTOCOL='sparse')
    lock_graph('canonical', canonical, official_env)
    canonical_lock = canonical / 'Cargo.lock'
    canonical_digest = sha(canonical_lock)
    with canonical_lock.open('rb') as stream:
        canonical_records = [entry for entry in tomllib.load(stream)['package'] if 'source' in entry]
    check('the independent stock lockfile uses the canonical crates.io source and pinned checksums',
          {entry['name'] for entry in canonical_records} == set(PACKAGES)
          and all(entry['source'] == 'registry+https://github.com/rust-lang/crates.io-index'
                  and (entry['version'], entry['checksum']) == PACKAGES[entry['name']] for entry in canonical_records))
    check('the authenticated crates.io replacement fetches both exact archives with an unchanged canonical lockfile',
          fetch('replacement', directory=canonical, replace=True) == expected and sha(canonical_lock) == canonical_digest)

    api('cargo-public-revoke', management + '/grants', 'PUT', {**grant, 'read': False})
    local_trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    local = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=local_trust), NoRedirect())
    for name, (version, _) in PACKAGES.items():
        status = 200
        try:
            read(local, f'{root}/download/{name}/{version}', 1 << 20, {'Authorization': reader})
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        check(f'current repository grant gates the stored {name} archive', status == 403)
    return {'checks': checks, 'archive_sha256': expected, 'index': INDEX, 'download_base': DOWNLOAD,
            'lock_sha256': sha(lock), 'canonical_lock_sha256': canonical_digest}
