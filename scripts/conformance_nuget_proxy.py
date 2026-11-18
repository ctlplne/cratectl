# SPDX-License-Identifier: BUSL-1.1
"""Restore only owned inert packages through a scoped NuGet flat-container proxy."""

import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import socket
import threading
import uuid
import xml.etree.ElementTree as XML
import zipfile

from bounded_client import run_owned_client
from qualification_contract import dotnet_sdk_pin

REPOSITORY = 'cratectl-nuget-proxy'
ORIGIN = '/cratectl-nuget-origin/'
VERSION = '1.0.0'
APPLICATION = 'Cratectl.Proxy.Application'
DEPENDENCY = 'Cratectl.Proxy.Dependency'


def inert_package(package_id, dependency=None):
    dependencies = '' if dependency is None else (
        f'<dependencies><group targetFramework="net10.0"><dependency id="{dependency}" '
        f'version="[{VERSION}]" /></group></dependencies>')
    manifest = (f'<?xml version="1.0" encoding="utf-8"?><package><metadata><id>{package_id}</id>'
                f'<version>{VERSION}</version><authors>cratectl fixture</authors>'
                f'<description>Owned inert proxy fixture</description>{dependencies}</metadata></package>').encode()
    payload = f'Owned inert content for {package_id}\n'.encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', allowZip64=False) as archive:
        for name, value in ((package_id + '.nuspec', manifest), ('lib/net10.0/_._', b''), ('content/owned.txt', payload)):
            item = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            archive.writestr(item, value)
    return stream.getvalue(), manifest, payload


@contextmanager
def flat_origin(files):
    requests = []

    class Origin(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            data = files.get(self.path)
            self.send_response(404 if data is None else 200)
            data = data or b''
            self.send_header('Cache-Control', 'max-age=300')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    with Origin(('::1', 38443), Handler) as origin:
        thread = threading.Thread(target=origin.serve_forever, name='cratectl-nuget-origin')
        thread.start()
        try:
            yield requests
        finally:
            origin.shutdown()
            thread.join(5)
            if thread.is_alive():
                raise ValueError('owned NuGet origin did not stop')


def proxy_nuget(h):
    scope = h.PRIVATE / 'cratectl-nuget-proxy'
    scope.mkdir(mode=0o700)
    native = f'/nuget/{REPOSITORY}/'
    management = f'/api/v1/repositories/{REPOSITORY}'
    packages = {APPLICATION: inert_package(APPLICATION, DEPENDENCY), DEPENDENCY: inert_package(DEPENDENCY)}
    files = {}
    fixtures = {}

    def package_path(package_id):
        key = package_id.lower()
        return f'{key}/{VERSION}/{key}.{VERSION}.nupkg'

    for package_id, (package, manifest, payload) in packages.items():
        source = ORIGIN + package_path(package_id)
        files[ORIGIN + package_id.lower() + '/index.json'] = b'{"versions":["1.0.0"]}'
        files[source] = package
        files[source + '.sha512'] = base64.b64encode(hashlib.sha512(package).digest())
        fixtures[package_id] = {name: hashlib.sha256(data).hexdigest() for name, data in
                                [('nupkg', package), ('nuspec', manifest), ('payload', payload)]}

    dotnet = shutil.which('dotnet')
    h.check('stock dotnet SDK executable is available', dotnet is not None)
    public_env = {key: value for key, value in os.environ.items()
                  if not key.upper().startswith(('CRATECTL_', 'PG', 'DOTNET_', 'NUGET_', 'MSBUILD'))
                  and key.upper() not in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}
    public_env.update(DOTNET_CLI_HOME=str(scope / 'dotnet'), DOTNET_CLI_TELEMETRY_OPTOUT='1',
                      DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true',
                      DOTNET_GENERATE_ASPNET_CERTIFICATE='false', NUGET_PLUGIN_PATHS='', NO_PROXY='127.0.0.1,::1')
    with (scope / 'dotnet-version.log').open('xb') as log:
        code, output = run_owned_client([dotnet, '--version'], h.ROOT, public_env, timeout=15, output_sink=log)
    sdk = output.strip()
    h.check('stock dotnet SDK matches the exact repository pin', code == 0 and sdk == dotnet_sdk_pin(h.ROOT))
    with Path(dotnet).resolve().open('rb') as binary:
        dotnet_sha = hashlib.file_digest(binary, 'sha256').hexdigest()
    h.result['nuget_proxy'] = {'sdk': sdk, 'dotnet_sha256': dotnet_sha, 'fixtures': fixtures, 'loopback_http': True}

    config = scope / 'NuGet.Config'
    document = XML.Element('configuration')
    sources = XML.SubElement(document, 'packageSources')
    XML.SubElement(sources, 'clear')
    XML.SubElement(sources, 'add', key='cratectl', value=h.BASE + native + 'index.json', allowInsecureConnections='true')
    credentials = XML.SubElement(XML.SubElement(document, 'packageSourceCredentials'), 'cratectl')
    XML.SubElement(credentials, 'add', key='Username', value='token')
    XML.SubElement(credentials, 'add', key='ClearTextPassword', value=h.tokens['reader'])
    XML.ElementTree(document).write(config, encoding='utf-8', xml_declaration=True)
    config.chmod(0o600)

    def mutate(path, data):
        return h.req(management + path, method='PUT', data=data, key=uuid.uuid4().hex)[0]

    def decide(package_id, decision):
        return mutate('/decisions', {'path': f'nuget-packages/{package_id.lower()}/{VERSION}.nupkg',
                                       'digest': fixtures[package_id]['nupkg'], 'decision': decision})

    def restore(label, allowed=True):
        consumer = scope / label
        consumer.mkdir(mode=0o700)
        project = consumer / 'Owned.csproj'
        project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>'
                           '<NuGetAudit>false</NuGetAudit><EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
                           '</PropertyGroup><ItemGroup>'
                           f'<PackageReference Include="{APPLICATION}" Version="[{VERSION}]" />'
                           '</ItemGroup></Project>')
        installed = consumer / 'packages'
        extra = dict(public_env, NUGET_PACKAGES=str(installed), NUGET_HTTP_CACHE_PATH=str(consumer / 'http-cache'),
                     NUGET_PLUGINS_CACHE_PATH=str(consumer / 'plugin-cache'))
        args = [dotnet, 'restore', project, '--configfile', config, '--packages', installed, '--no-http-cache',
                '--force', '--verbosity', 'minimal']
        with (consumer / 'restore.log').open('xb') as log:
            code, output = run_owned_client(args, consumer, extra, timeout=70, capture_limit=32 << 10, output_sink=log)
        if not allowed:
            h.check(f'stock dotnet fails closed with current package review {label}', code != 0 and 'NU1101' in output)
            return
        h.check(f'stock dotnet restore succeeds {label}', code == 0)
        assets = json.loads((consumer / 'obj/project.assets.json').read_text())
        h.check(f'stock dotnet resolves the exact application and transitive dependency {label}',
                set(assets['libraries']) == {f'{package_id}/{VERSION}' for package_id in packages})
        for package_id, (package, manifest, payload) in packages.items():
            key = package_id.lower()
            folder = installed / key / VERSION
            h.check(f'stock dotnet retains exact package, manifest and inert content for {package_id} {label}',
                    (folder / f'{key}.{VERSION}.nupkg').read_bytes() == package and
                    (folder / f'{key}.nuspec').read_bytes() == manifest and (folder / 'content/owned.txt').read_bytes() == payload)

    with flat_origin(files) as requests:
        h.repository(REPOSITORY, 'nuget', review=True, mode='proxy', access='restricted', settings={
            'upstream': {'url': 'http://[::1]:38443' + ORIGIN, 'networks': ['::1/128']},
            'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'require_checksum': True}})
        h.check('ungranted stock source and other tenant requests make no origin request',
                h.req(native + 'index.json', 'reader')[0] == 403 and h.req(native + 'index.json', 'other')[0] == 404 and not requests)
        h.check('reader receives the owned repository grant', mutate('/grants', {'actor': 'reader', 'read': True}) == 200)
        index_code, index_body, _ = h.req(native + 'index.json', 'reader')
        h.check('NuGet discovery advertises the scoped cratectl flat address', index_code == 200 and
                json.loads(index_body)['resources'] == [{'@id': h.BASE + native + 'flat/', '@type': 'PackageBaseAddress/3.0.0'}])
        restore('unreviewed', allowed=False)
        for package_id in packages:
            h.check('cold exact request stages the reviewed archive ' + package_id,
                    h.req(native + 'flat/' + package_path(package_id), 'reader')[0] == 403 and decide(package_id, 'allowed') == 200)
        restore('cold-dependency-catalog')
        h.check('upstream requests stay on canonical indexes, archives and SHA-512 sidecars',
                set(requests) == set(files) and len(requests) == len(files))
        app_flat = native + 'flat/' + APPLICATION.lower() + '/'
        code, body, _ = h.req(app_flat + VERSION + '/' + APPLICATION.lower() + '.nuspec', 'reader')
        h.check('native manifest bytes come from the verified archive', code == 200 and body == packages[APPLICATION][1])
        count = len(requests)
        h.stop()
        h.start()
        restore('warm-restart')
        h.check('restart and warm restore make no origin transfer', len(requests) == count)
        h.check('current exact denial applies to cached version advertisements and bytes', decide(APPLICATION, 'denied') == 200 and
                h.req(app_flat + 'index.json', 'reader')[0] == 404 and
                h.req(native + 'flat/' + package_path(APPLICATION), 'reader')[0] == 403)
        restore('denied', allowed=False)
        h.check('current policy can restore the exact retained digest', decide(APPLICATION, 'allowed') == 200)
        restore('allowed-again')
        h.check('repeated policy changes and isolated stock restores keep the warm origin idle', len(requests) == count)
        h.result['nuget_proxy']['origin_requests'] = count
