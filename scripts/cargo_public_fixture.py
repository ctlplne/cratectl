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


REPOSITORY = 'cratectl-public-cargo'
INDEX = 'https://index.crates.io'
DOWNLOAD = 'https://static.crates.io/crates'
PACKAGES = {
    'form_urlencoded': ('1.2.1', 'e13624c2627564efccf4934284bdd98cbaa14e79b0b5a141218e507b3a823456'),
    'percent-encoding': ('2.3.1', 'e3148f5046208a5d56bcfc03053e3ca6334e51da8dfb19b6cdc8b306fae3283e'),
}


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

    def fetch(label, resolve=False):
        home, child = cargo_home(work, 'cargo-public-home-' + label, 'sparse+' + root + '/index/', env, reader)
        if resolve:
            call('cargo-public-resolve', cargo, 'generate-lockfile', cwd=project, environment=child, timeout=60)
            call('cargo-public-pin-leaf', cargo, 'update', '-p', 'percent-encoding', '--precise', PACKAGES['percent-encoding'][0],
                 cwd=project, environment=child, timeout=60)
        call('cargo-public-fetch-' + label, cargo, 'fetch', '--locked', cwd=project, environment=child, timeout=60)
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
    return {'checks': checks, 'archive_sha256': expected, 'index': INDEX, 'download_base': DOWNLOAD, 'lock_sha256': sha(lock)}
