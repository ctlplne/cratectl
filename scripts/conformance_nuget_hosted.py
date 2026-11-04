# SPDX-License-Identifier: BUSL-1.1
"""Owned inert NuGet fixtures exercised by the real conformance harness.

The registry never executes payloads. Restore evaluates only the installed SDK's
project rules; these packages contain no build targets, scripts or assemblies.
"""

import hashlib
import gzip
import io
import json
import platform
import re
import shutil
import uuid
import xml.etree.ElementTree as XML
import zipfile
from pathlib import Path
from urllib.parse import urlencode
from nuget_feed_cases import cases as metadata_cases, archive as metadata_archive, difference_paths


def hosted(h):
    check, req, run = h.check, h.req, h.run
    dotnet = shutil.which('dotnet')
    check('actual dotnet SDK is available for hosted NuGet', dotnet is not None)
    sdk = run([dotnet, '--version']).strip()
    check('actual dotnet SDK has a bounded version identity', re.fullmatch(r'10\.[0-9]{1,3}\.[0-9]{1,4}', sdk) is not None)
    h.result['nuget_sdk_version'] = sdk
    with Path(dotnet).resolve().open('rb') as binary:
        h.result['nuget_dotnet_sha256'] = hashlib.file_digest(binary, 'sha256').hexdigest()
    h.result['nuget_fixture_sha256'] = {}
    work = h.PRIVATE / 'nuget'
    work.mkdir(mode=0o700)
    source = h.BASE + '/nuget/dotnet/index.json'
    h.repository('dotnet', 'nuget', review=True)
    h.repository('dotnet', 'nuget', 'other')
    config = work / 'NuGet.Config'
    document = XML.Element('configuration')
    sources = XML.SubElement(document, 'packageSources')
    XML.SubElement(sources, 'clear')
    XML.SubElement(sources, 'add', key='cratectl', value=source, allowInsecureConnections='true')
    credentials = XML.SubElement(XML.SubElement(document, 'packageSourceCredentials'), 'cratectl')
    XML.SubElement(credentials, 'add', key='Username', value='token')
    XML.SubElement(credentials, 'add', key='ClearTextPassword', value=h.tokens['reader'])
    XML.ElementTree(document).write(config, encoding='utf-8', xml_declaration=True)
    config.chmod(0o600)
    extra = {'DOTNET_CLI_HOME': str(work / 'home'), 'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'NUGET_HTTP_CACHE_PATH': str(work / 'http-cache'), 'NUGET_PACKAGES': str(work / 'packages'), 'NUGET_AUDIT_MODE': 'direct'}
    probe = work / 'probe'
    probe.mkdir(mode=0o700)
    fixture_root = Path(__file__).resolve().parent / 'fixtures/nuget-feed'
    for filename in ['Program.cs', 'Probe.csproj']:
        shutil.copy2(fixture_root / filename, probe / filename)
    run([dotnet, 'build', probe / 'Probe.csproj', '--configfile', config, '--output', probe / 'out', '--verbosity', 'quiet'], probe, extra)
    h.result['nuget_protocol_probe_sha256'] = hashlib.sha256((probe / 'out/Probe.dll').read_bytes()).hexdigest()
    h.result['nuget_protocol_library_sha256'] = hashlib.sha256((probe / 'out/NuGet.Protocol.dll').read_bytes()).hexdigest()

    def metadata(listed=True):
        result = json.loads(run([dotnet, probe / 'out/Probe.dll', config, 'Cratectl.Proof.Application'], probe, extra))
        check('actual SDK metadata probe uses the runner architecture', result['architecture'] == {'x86_64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()])
        check('actual SDK resolves the advertised native search resource', result['search_endpoint_count'] == 1)
        rows = {row['version']: row for row in result['rows']}
        check('actual SDK registration retains both application versions', set(rows) == {'1.0.0', '2.0.0'})
        check('actual SDK registration reads durable listing state ' + str(listed), rows['1.0.0']['listed'] is listed and rows['2.0.0']['listed'] is True)
        check('actual SDK registration resolves target framework and exact dependency interval', all(row['groups'] == [{'framework': 'net10.0', 'packages': [{'id': 'Cratectl.Proof.Dependency', 'min': '1.0.0', 'max': '1.0.0', 'include_min': True, 'include_max': True}]}] for row in rows.values()))
        check('actual SDK protocol library has a bounded observed identity', re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}', result['library_version']) is not None)
        h.result['nuget_protocol_library_version'] = result['library_version']

    def search():
        result = json.loads(run([dotnet, 'package', 'search', 'Cratectl.Proof.Application', '--configfile', config, '--source', source, '--format', 'json', '--take', '20'], work, extra))
        rows = [row for group in result.get('searchResult', []) for row in group.get('packages', [])]
        check('stock dotnet package search uses native feed discovery', not result.get('problems') and len(rows) == 1 and rows[0]['id'] == 'Cratectl.Proof.Application' and rows[0]['latestVersion'] == '2.0.0')

    def registration():
        code, data, headers = req('/nuget/dotnet/registration/cratectl.proof.application/index.json', 'reader')
        check('NuGet registration has the required compressed representation', code == 200 and headers.get('Content-Encoding') == 'gzip')
        return json.loads(gzip.decompress(data))
    packages = {}

    def package(label, name, version, dependency=False, other=False):
        dependency_xml = '<dependencies><group targetFramework="net10.0"><dependency id="Cratectl.Proof.Dependency" version="[1.0.0]" /></group></dependencies>' if dependency else ''
        nuspec = ('<?xml version="1.0" encoding="utf-8"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>' + name + '</id><version>' + version + '</version><authors>cratectl owned fixture</authors><description>Inert native restore fixture</description>' + dependency_xml + '</metadata></package>').encode()
        payload = ('Owned fixture ' + label + (' tenant B' if other else ' tenant A') + '\n').encode()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=False) as archive:
            for path, value in [(name + '.nuspec', nuspec), ('lib/net10.0/_._', b''), ('content/owned.txt', payload)]:
                info = zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, value)
        data = stream.getvalue()
        path = work / (label + '.nupkg')
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        h.result['nuget_fixture_sha256'][label] = digest
        packages[label] = (name, version, data, nuspec, payload)
        return path, digest

    def push(path, token='admin', duplicate=False, denied=False):
        # Bind an opaque key to its option, including a valid generated key
        # whose first base64url character is '-'. Never regenerate such keys.
        args = [dotnet, 'nuget', 'push', path, '--source', source, '--api-key=' + h.tokens[token], '--no-symbols']
        if duplicate:
            args.append('--skip-duplicate')
        run(args, work, extra, expect_failure=denied)

    def decide(name, version, digest, decision):
        path = 'nuget-packages/' + name.lower() + '/' + version + '.nupkg'
        code, _, _ = req('/api/v1/repositories/dotnet/decisions', method='PUT', data={'path': path, 'digest': digest, 'decision': decision}, key=uuid.uuid4().hex)
        check('NuGet exact-digest decision ' + name + ' ' + version + ' ' + decision, code == 200)
        return path

    def restore(label, version, expect_failure=False):
        consumer = work / label
        consumer.mkdir(mode=0o700)
        project = consumer / 'Owned.csproj'
        project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><NuGetAudit>false</NuGetAudit><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><PackageReference Include="Cratectl.Proof.Application" Version="[' + version + ']" /></ItemGroup></Project>')
        # Fresh package and HTTP caches ensure every attempt exercises the server.
        package_root = consumer / 'packages'
        run([dotnet, 'restore', project, '--configfile', config, '--packages', package_root, '--no-http-cache', '--force', '--verbosity', 'minimal'], consumer, {**extra, 'NUGET_HTTP_CACHE_PATH': str(consumer / 'http-cache')}, expect_failure=expect_failure)
        if expect_failure:
            return
        assets = json.loads((consumer / 'obj/project.assets.json').read_text())
        check('stock dotnet resolves app and transitive dependency ' + label, 'Cratectl.Proof.Application/' + version in assets['libraries'] and 'Cratectl.Proof.Dependency/1.0.0' in assets['libraries'])
        for fixture in ['dependency', 'application_' + version[0]]:
            name, actual_version, data, nuspec, payload = packages[fixture]
            folder = package_root / name.lower() / actual_version
            nupkg = folder / (name.lower() + '.' + actual_version + '.nupkg')
            check('stock dotnet retains exact nupkg ' + label + ' ' + fixture, nupkg.read_bytes() == data)
            check('stock dotnet extracts exact inert payload ' + label + ' ' + fixture, (folder / 'content/owned.txt').read_bytes() == payload)
            check('stock dotnet dependency nuspec is original ' + label + ' ' + fixture, (folder / (name.lower() + '.nuspec')).read_bytes() == nuspec)

    dep, dep_digest = package('dependency', 'Cratectl.Proof.Dependency', '1.0.0')
    app1, app1_digest = package('application_1', 'Cratectl.Proof.Application', '1.0.0', True)
    app2, app2_digest = package('application_2', 'Cratectl.Proof.Application', '2.0.0', True)
    # This public synthetic value is deliberately not a credential. Exercise the
    # actual SDK parser and real registry's authentication boundary before any
    # dependency publication; invalid authentication must leave no reference.
    parser_probe = run([dotnet, 'nuget', 'push', dep, '--source', source,
                        '--api-key=-cratectl_owned_invalid_parser_probe_000000', '--no-symbols'],
                       work, extra, expect_failure=True)
    check('stock dotnet consumes a leading-hyphen API key without treating it as an option',
          '401 (Unauthorized)' in parser_probe and 'No API Key was provided' not in parser_probe)
    check('invalid parser-probe key publishes no NuGet dependency',
          req('/nuget/dotnet/flat/cratectl.proof.dependency/index.json')[0] == 404)
    for path in [dep, app1, app2]:
        push(path)
    push(app1, duplicate=True)
    push(app1, token='reader', denied=True)
    flat = '/nuget/dotnet/flat/cratectl.proof.application/'
    package_url = flat + '1.0.0/cratectl.proof.application.1.0.0.nupkg'
    manifest_url = flat + '1.0.0/cratectl.proof.application.nuspec'
    check('NuGet unreviewed index does not expose versions', req(flat + 'index.json', 'reader')[0] == 404)
    check('NuGet unreviewed package and manifest are blocked', req(package_url, 'reader')[0] == 403 and req(manifest_url, 'reader')[0] == 403)
    restore('unreviewed-consumer', '1.0.0', True)
    for label, digest in [('dependency', dep_digest), ('application_1', app1_digest), ('application_2', app2_digest)]:
        name, version = packages[label][:2]
        decide(name, version, digest, 'allowed')
    check('NuGet normalized complete version list', json.loads(req(flat + 'index.json', 'reader')[1])['versions'] == ['1.0.0', '2.0.0'])
    for url, expected in [(package_url, packages['application_1'][2]), (manifest_url, packages['application_1'][3])]:
        code, data, headers = req(url, 'reader')
        check('NuGet native exact content ' + url.rsplit('/', 1)[-1], code == 200 and data == expected)
        etag = headers['Etag']
        code, data, _ = req(url, 'reader', headers={'Range': 'bytes=1-7'})
        check('NuGet native range ' + url.rsplit('/', 1)[-1], code == 206 and data == expected[1:8])
        check('NuGet native conditional ' + url.rsplit('/', 1)[-1], req(url, 'reader', headers={'If-None-Match': etag})[0] == 304)
    restore('consumer-one', '1.0.0')
    restore('consumer-two', '2.0.0')
    metadata()
    search()
    check('NuGet registration pages advertise complete numeric bounds', registration()['items'][0]['lower'] == '1.0.0' and registration()['items'][0]['upper'] == '2.0.0')

    def unlist(token='admin', denied=False):
        run([dotnet, 'nuget', 'delete', 'Cratectl.Proof.Application', '1.0.0', '--source', source, '--api-key=' + h.tokens[token], '--non-interactive'], work, extra, expect_failure=denied)

    def listing_state(expected):
        reference = '/api/v1/repositories/dotnet/artifacts/reference?' + urlencode({'path': 'nuget-packages/cratectl.proof.application/1.0.0.nupkg'})
        code, raw, _ = req(reference)
        item = json.loads(raw) if code == 200 else {}
        check('NuGet durable native listing state ' + str(expected), code == 200 and item.get('metadata', {}).get('listed', True) is expected and item.get('digest') == app1_digest)

    unlist(token='reader', denied=True)
    listing_state(True)
    unlist()
    unlist()  # A retry must succeed while retaining the immutable version.
    listing_state(False)
    metadata(False)
    search()
    code, raw, _ = req('/nuget/dotnet/query?q=Cratectl.Proof.Application', 'reader')
    check('NuGet search removes unlisted versions while retaining the latest listed one', code == 200 and [row['version'] for row in json.loads(raw)['data'][0]['versions']] == ['2.0.0'])
    check('NuGet unlisting retains the complete flat index', json.loads(req(flat + 'index.json', 'reader')[1])['versions'] == ['1.0.0', '2.0.0'])
    restore('unlisted-pinned-consumer', '1.0.0')
    check('NuGet unlisting retains original package and manifest bytes', req(package_url, 'reader')[1] == packages['application_1'][2] and req(manifest_url, 'reader')[1] == packages['application_1'][3])
    h.stop()
    h.start()
    listing_state(False)
    metadata(False)
    search()
    restore('unlisted-restarted-pinned-consumer', '1.0.0')
    listing_endpoint = '/nuget/dotnet/api/v2/package/Cratectl.Proof.Application/1.0.0'
    key_headers = {'X-NuGet-ApiKey': h.tokens['admin']}
    check('NuGet native POST relists the version', req(listing_endpoint, method='POST', headers=key_headers)[0] == 200)
    check('NuGet native POST relist retries succeed', req(listing_endpoint, method='POST', headers=key_headers)[0] == 200)
    listing_state(True)
    metadata()
    restore('relisted-pinned-consumer', '1.0.0')
    check('NuGet other tenant initially cannot see matching repository coordinate', req(package_url, 'other')[0] == 404)
    other, _ = package('other_application_1', 'Cratectl.Proof.Application', '1.0.0', True, True)
    push(other, token='other')
    check('NuGet colliding tenant coordinates retain distinct exact bytes', req(package_url, 'other')[1] == packages['other_application_1'][2] and req(package_url, 'reader')[1] == packages['application_1'][2])
    decide('Cratectl.Proof.Application', '1.0.0', app1_digest, 'denied')
    check('NuGet relisting never overrides current content denial', req(listing_endpoint, method='POST', headers=key_headers)[0] == 200 and req(package_url, 'reader')[0] == 403)
    restore('denied-consumer', '1.0.0', True)
    check('NuGet denial covers direct content and manifest', req(package_url, 'reader')[0] == 403 and req(manifest_url, 'reader')[0] == 403)
    code, raw, _ = req('/nuget/dotnet/query?q=Cratectl.Proof.Application', 'reader')
    check('NuGet current denial removes registration and search metadata', req('/nuget/dotnet/registration/cratectl.proof.application/1.0.0/catalog.json', 'reader')[0] == 403 and code == 200 and [row['version'] for row in json.loads(raw)['data'][0]['versions']] == ['2.0.0'])
    decide('Cratectl.Proof.Application', '1.0.0', app1_digest, 'allowed')
    h.stop()
    h.start()
    restore('restarted-consumer', '1.0.0')
    check('NuGet exact content survives actual registry restart', req(package_url, 'reader')[1] == packages['application_1'][2])

    # Compare actual public SDK Nuspec meaning with that same SDK's HTTP
    # registration reader. This covers production rendering, routing and gzip;
    # it does not infer JSON interoperability from re-encoded XML alone.
    h.repository('dotnet-metadata', 'nuget')
    corpus = metadata_cases(extended=True)
    for case in corpus:
        case['archive_sha256'] = hashlib.sha256(metadata_archive(case)).hexdigest()
    original = json.dumps(corpus[:44], sort_keys=True, separators=(',', ':')).encode()
    check('all original44HTTP metadata fixtures remain byte-identical', hashlib.sha256(original).hexdigest() == '911a48eef175c1075cebc742c47b9a615459a157e71d326d062b4a80780c9bca')
    encoded = json.dumps(corpus, sort_keys=True, separators=(',', ':')).encode()
    check('owned NuGet HTTP metadata corpus stays bounded', len(corpus) <= 64 and len(encoded) <= 2 << 20)
    corpus_file = work / 'metadata-corpus.json'
    corpus_file.write_bytes(encoded)
    corpus_file.chmod(0o600)
    config_corpus = work / 'NuGet.Metadata.Config'
    document_corpus = XML.parse(config)
    document_corpus.find('./packageSources/add').set('value', h.BASE + '/nuget/dotnet-metadata/index.json')
    document_corpus.write(config_corpus, encoding='utf-8', xml_declaration=True)
    config_corpus.chmod(0o600)
    for case in corpus:
        package = metadata_archive(case)
        check('owned NuGet archive matches the retained fixture identity ' + case['label'], hashlib.sha256(package).hexdigest() == case['archive_sha256'])
        boundary = 'cratectl-' + hashlib.sha256(package).hexdigest()
        check('owned NuGet multipart boundary is distinct ' + case['label'], boundary.encode() not in package)
        body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="package"; filename="owned.nupkg"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + package + ('\r\n--' + boundary + '--\r\n').encode()
        code, _, _ = req('/nuget/dotnet-metadata/api/v2/package', method='PUT', data=body, headers={'Content-Type': 'multipart/form-data; boundary=' + boundary, 'X-NuGet-ApiKey': h.tokens['admin']})
        check('publish owned NuGet HTTP metadata case ' + case['label'], code == 201)

    def compare_metadata_corpus(phase):
        output = run([dotnet, probe / 'out/Probe.dll', config_corpus, '--corpus', corpus_file], probe, extra)
        observed = json.loads(output)
        rows = observed['rows']
        mismatch = [row['index'] for row in rows if not row['valid'] or not row['matches']]
        h.result['nuget_metadata_contract'] = {'cases': len(corpus), 'fixture_sha256': hashlib.sha256(encoded).hexdigest(), 'observations_sha256': hashlib.sha256(output.encode()).hexdigest(), 'mismatch_indexes': mismatch, 'phase': phase}
        # Only owned synthetic metadata appears here; the safe exporter retains
        # hashes/counts/indexes instead of arbitrary messages or client output.
        h.result['nuget_metadata_mismatches'] = [row for row in rows if not row['valid'] or not row['matches']][:16]
        h.result['nuget_metadata_diagnostics'] = [{'index': row['index'], 'failed': not row['valid'], 'paths': difference_paths(row.get('original', {}), row.get('http', {}))[:64]} for row in h.result['nuget_metadata_mismatches']]
        check('actual SDK HTTP corpus uses the exact native library and architecture ' + phase, observed['library_version'] == h.result['nuget_protocol_library_version'] and observed['architecture'] == {'x86_64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()])
        check('actual SDK HTTP corpus returns every owned case ' + phase, [row['index'] for row in rows] == list(range(len(corpus))))
        check('actual SDK HTTP framework/range/preference/list semantics match original Nuspec ' + phase, not mismatch)

    compare_metadata_corpus('published')
    h.stop()
    h.start()
    compare_metadata_corpus('restarted')


if __name__ == '__main__':
    raise SystemExit('Run scripts/conformance.py nuget --require-clean-build (or all); this module reuses the owned registry/database lifecycle.')
