#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Generate SPDX and CycloneDX sidecars for exact local Linux archives."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import quote

from bounded_client import run_owned_client
from package_linux import BINARIES, ROOT, digest, publish
from verify_linux_candidate import require, unique_members, verify


WEB_RUNTIME = ('react', 'react-dom', 'scheduler')
ARCHITECTURES = ('amd64', 'arm64')
GO_SUM = re.compile(r'h1:[A-Za-z0-9+/]{43}=')
NPM_INTEGRITY = re.compile(r'sha512-[A-Za-z0-9+/]{86}==')


@dataclass(frozen=True)
class Component:
    ref: str
    name: str
    version: str
    kind: str
    checksum: str = ''
    filename: str = ''
    purl: str = ''
    license: str = ''
    source_integrity: str = ''


def command(*args):
    env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off', 'GOPROXY': 'off'}
    code, output = run_owned_client(args, ROOT, env, timeout=30, output_limit=1 << 20, capture_limit=1 << 20)
    require(code == 0, 'cannot read local build identity: ' + Path(args[0]).name)
    return output.strip()


def archive_checksums(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'checksums must come from a regular file')
        raw = source.read(257)
    names = ['cratectl-linux-' + arch + '.tar.gz' for arch in ARCHITECTURES]
    pattern = ''.join(r'([a-f0-9]{64})  ' + re.escape(name) + '\n' for name in names).encode('ascii')
    found = re.fullmatch(pattern, raw)
    require(found is not None, 'canonical two-platform SHA256SUMS required')
    return dict(zip(names, (entry.decode('ascii') for entry in found.groups())))


def locked_web_modules(lock, notices):
    components = []
    for name in WEB_RUNTIME:
        member = lock['packages']['node_modules/' + name]
        version, integrity = member['version'], member['integrity']
        require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) and NPM_INTEGRITY.fullmatch(integrity)
                and member.get('license') == 'MIT' and member.get('dev', False) is False
                and notices.splitlines().count(f'--- {name} {version} ---') == 1,
                'embedded npm runtime inventory differs from pinned notices')
        components.append(Component('npm-' + name, name, version, 'library', purl=f'pkg:npm/{name}@{version}',
                                    license='MIT', source_integrity=integrity))
    return components


def linked_modules(info, identity, name, checksums):
    settings = unique_members([(entry['Key'], entry['Value']) for entry in info['Settings']])
    platform, architecture = identity['platform'].split('/')
    require(info['GoVersion'] == 'go' + identity['go_version']
            and info['Path'] == 'ctlplne.dev/cratectl/cmd/' + name
            and info['Main']['Path'] == 'ctlplne.dev/cratectl' and info['Main'].get('Replace') is None
            and all(settings.get(key) == expected for key, expected in (
                ('vcs.revision', identity['candidate']), ('vcs.modified', 'false'),
                ('GOOS', platform), ('GOARCH', architecture), ('CGO_ENABLED', '0'))),
            'binary build metadata differs from the archived source and platform')
    require(type(info['Deps']) is list and 0 < len(info['Deps']) <= 1024, 'missing or oversized linked module inventory')
    linked = {}
    for module in info['Deps']:
        path, version, checksum = module['Path'], module['Version'], module['Sum']
        require(re.fullmatch(r'[A-Za-z0-9._~/-]{1,512}', path)
                and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*', version)
                and GO_SUM.fullmatch(checksum) and checksum == checksums.get((path, version))
                and module.get('Replace') is None, 'unbound or replaced module in binary build metadata')
        purl = 'pkg:golang/' + quote(path, safe='/') + '@' + quote(version, safe='')
        ref = 'go-' + hashlib.sha256(purl.encode('ascii')).hexdigest()
        require(ref not in linked, 'duplicate linked module in binary build metadata')
        linked[ref] = Component(ref, path, version, 'library', purl=purl, source_integrity=checksum)
    return linked


def inspect(path, expected, candidate, go_sum, web, go):
    with tempfile.TemporaryDirectory(prefix='cratectl-sbom-binaries-', dir=path.parent) as folder:
        extracted = Path(folder)
        manifest = verify(path, expected, staging=extracted)
        require(manifest['candidate'] == candidate and path.name == 'cratectl-' + manifest['platform'].replace('/', '-') + '.tar.gz'
                and all(digest(ROOT / source) == hash_value for source, hash_value in manifest['source_sha256'].items()),
                'archive source inputs differ from the clean checkout')
        artifact = Component('archive', 'cratectl ' + manifest['platform'], candidate, 'application',
                             checksum=expected, filename=path.name, license='BUSL-1.1')
        stdlib = Component('go-stdlib', 'Go standard library', manifest['go_version'], 'library')
        components = {stdlib.ref: stdlib, **{module.ref: module for module in web}}
        relations = []
        for name in BINARIES:
            component = Component(name, name, candidate, 'application', checksum=manifest['binaries'][name]['sha256'],
                                  filename=name, license='BUSL-1.1')
            components[name] = component
            relations.append((artifact.ref, 'CONTAINS', name))
            info = json.loads(command(go, 'version', '-m', '-json', extracted / name), object_pairs_hook=unique_members)
            linked = linked_modules(info, manifest, name, go_sum)
            components.update(linked)
            relations.extend((name, 'STATIC_LINK', module) for module in [stdlib.ref, *linked])
        relations.extend(('cratectld', 'CONTAINS', module.ref) for module in web)
        return artifact, sorted(components.values(), key=lambda item: item.ref), sorted(relations)


def spdx(artifact, components, relations, timestamp):
    def package(item):
        result = {'SPDXID': 'SPDXRef-' + item.ref, 'name': item.name, 'versionInfo': item.version,
                  'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
                  'licenseDeclared': item.license or 'NOASSERTION', 'copyrightText': 'NOASSERTION'}
        if item.checksum:
            result.update(packageFileName=item.filename, checksums=[{'algorithm': 'SHA256', 'checksumValue': item.checksum}])
        if item.purl:
            result['externalRefs'] = [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': item.purl}]
        if item.source_integrity:
            result['comment'] = 'Source package integrity value ' + item.source_integrity
        return result

    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': artifact.filename, 'documentNamespace': 'https://ctlplne.dev/spdxdocs/cratectl-' + artifact.checksum,
            'creationInfo': {'created': timestamp, 'creators': ['Tool: cratectl-linux-candidate-sbom-v1']},
            'packages': [package(item) for item in (artifact, *components)],
            'relationships': [{'spdxElementId': 'SPDXRef-' + source, 'relationshipType': relation,
                               'relatedSpdxElement': 'SPDXRef-' + target}
                              for source, relation, target in [('DOCUMENT', 'DESCRIBES', artifact.ref), *relations]]}


def cyclonedx(artifact, components, relations, timestamp):
    def package(item):
        result = {'type': item.kind, 'name': item.name, 'version': item.version, 'bom-ref': item.ref}
        if item.checksum:
            result['hashes'] = [{'alg': 'SHA-256', 'content': item.checksum}]
        if item.purl:
            result['purl'] = item.purl
        if item.license:
            result['licenses'] = [{'license': {'id': item.license}}]
        if item.source_integrity:
            result['properties'] = [{'name': 'ctlplne:source-package-integrity', 'value': item.source_integrity}]
        return result

    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'timestamp': timestamp, 'component': package(artifact)},
            'components': [package(item) for item in components],
            'dependencies': [{'ref': source, 'dependsOn': sorted(target for origin, _, target in relations if origin == source)}
                             for source in (artifact.ref, *BINARIES)]}


def emit(path, document):
    encoded = (json.dumps(document, indent=2, sort_keys=True) + '\n').encode('ascii')
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.cratectl-sbom-', delete=False) as output:
        staged = Path(output.name)
        try:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
            publish(path, staged)
        finally:
            staged.unlink(missing_ok=True)
    print(digest(path), path)


def main():
    os.umask(0o077)
    candidate = command('git', 'rev-parse', 'HEAD')
    require(re.fullmatch('[a-f0-9]{40}', candidate) and not command('git', 'status', '--porcelain'),
            'a clean corresponding Git checkout is required')
    directory = ROOT / '.cache/cratectl-linux-candidates' / candidate
    checksums = archive_checksums(directory / 'SHA256SUMS')
    timestamp = datetime.fromisoformat(command('git', 'show', '-s', '--format=%cI', candidate))
    timestamp = timestamp.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    rows = (ROOT / 'go.sum').read_text(encoding='ascii').splitlines()
    go_sum = unique_members([((name, version), checksum) for name, version, checksum in map(str.split, rows)])
    lock = json.loads((ROOT / 'web/package-lock.json').read_bytes(), object_pairs_hook=unique_members)
    notices = (ROOT / 'internal/consoleui/dist/third-party-notices.txt').read_text(encoding='utf-8')
    web = locked_web_modules(lock, notices)
    installed = ROOT / '.cache/go/bin/go'
    go = installed if installed.is_file() else 'go'
    for filename, checksum in checksums.items():
        archive, components, relations = inspect(directory / filename, checksum, candidate, go_sum, web, go)
        prefix = filename.removesuffix('.tar.gz')
        emit(directory / (prefix + '.spdx.json'), spdx(archive, components, relations, timestamp))
        emit(directory / (prefix + '.cdx.json'), cyclonedx(archive, components, relations, timestamp))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, EOFError) as error:
        raise SystemExit(f'Linux SBOM assembly failed: {error}') from None
