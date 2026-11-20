# SPDX-License-Identifier: BUSL-1.1
"""Build inert Conda v2 fixtures matching the public ZIP and Zstandard layout."""

from dataclasses import replace
import hashlib
import io
import json
import zipfile

from conda_hosted_fixture import fixtures, package_tar

REPOSITORY = 'cratectl-conda-modern-stock'
CHECKS = (
    'modern Conda publication binds the platform and preserves original ZIP bytes',
    'unreviewed modern and legacy archives stay out of both repodata buckets',
    'plain repodata keeps both archive formats under their exact native filenames and digests',
    'stock micromamba selects .conda archives over equivalent approved legacy archives',
    'fresh stock micromamba installs the exact inert .conda graph after restart',
    'current modern digest denial leaves bounded approved legacy fallback metadata',
    'stock micromamba uses the exact approved legacy dependency after modern digest denial',
    'fresh stock micromamba refuses the graph after denial of both compatible dependency archives',
)


def modern_packages(native):
    return tuple(replace(package, modern=True) for package in fixtures(native))


def make_modern_archive(package):
    from compression import zstd

    buffer = io.BytesIO()
    name = package.filename.removesuffix('.conda')
    components = {'info': [], 'pkg': []}
    for path, data in package.contents():
        components['info' if path.startswith('info/') else 'pkg'].append((path, data))
    with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(zipfile.ZipInfo('metadata.json'), b'{"conda_pkg_format_version":2}')
        for part in ('pkg', 'info'):
            tar = package_tar(components[part])
            member = zipfile.ZipInfo(part + '-' + name + '.tar.zst')
            with archive.open(member, 'w', force_zip64=True) as stream:
                stream.write(zstd.compress(tar, options={zstd.CompressionParameter.checksum_flag: 1}))
    return buffer.getvalue()


def evaluate_conda_modern(native, request, api, consume, restart):
    legacy_app, legacy_dependency = fixtures(native)[:2]
    app, dependency = modern_packages(native)[:2]
    packages = (legacy_app, legacy_dependency, app, dependency)
    contents = {p: p.archive() for p in packages}
    digests = {p: hashlib.sha256(contents[p]).hexdigest() for p in packages}
    management = '/api/v1/repositories/'
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def native_request(path, actor='reader', method='GET', body=None):
        return request(path, actor, method, body, repository=REPOSITORY)

    def view(subdir):
        code, raw, _ = native_request(subdir + '/repodata.json')
        if code != 200:
            raise ValueError(f'modern Conda catalog returned {code}')
        index = json.loads(raw)
        return {key: {name: item['sha256'] for name, item in index[key].items()} for key in ('packages', 'packages.conda')}

    def decide(package, decision):
        api('conda-modern-review-' + package.subdir + '-' + digests[package][:16] + '-' + decision,
            management + REPOSITORY + '/decisions', 'PUT',
            {'path': package.path, 'digest': digests[package], 'decision': decision})

    api('conda-modern-create', management.rstrip('/'), 'POST',
        {'name': REPOSITORY, 'format': 'conda', 'access': 'restricted', 'require_review': True})
    api('conda-modern-grant', management + REPOSITORY + '/grants', 'PUT',
        {'actor': 'cratectl-reader', 'read': True, 'write': False})
    check(CHECKS[0],
          native_request('win-64/' + app.filename, 'admin', 'PUT', contents[app])[0] == 400
          and all(native_request(p.path, 'admin', 'PUT', contents[p]) == (201, b'', digests[p]) for p in packages))
    check(CHECKS[1],
          all(view(platform) == {'packages': {}, 'packages.conda': {}} for platform in (native, 'noarch'))
          and native_request(app.path)[0] == 403)
    for package in packages:
        decide(package, 'allowed')
    check(CHECKS[2],
          view(native) == {'packages': {legacy_app.filename: digests[legacy_app]}, 'packages.conda': {app.filename: digests[app]}}
          and view('noarch') == {'packages': {legacy_dependency.filename: digests[legacy_dependency]},
                                 'packages.conda': {dependency.filename: digests[dependency]}})
    check(CHECKS[3],
          consume('modern-first', repository=REPOSITORY, graph=(app, dependency), download_only=True))
    restart()
    check(CHECKS[4],
          consume('modern-after-restart', repository=REPOSITORY, graph=(app, dependency)))
    decide(dependency, 'denied')
    check(CHECKS[5],
          view('noarch') == {'packages': {legacy_dependency.filename: digests[legacy_dependency]}, 'packages.conda': {}}
          and native_request(dependency.path)[0] == 403)
    check(CHECKS[6],
          consume('modern-fallback', repository=REPOSITORY, graph=(app, legacy_dependency)))
    decide(legacy_dependency, 'denied')
    check(CHECKS[7],
          consume('modern-denied', repository=REPOSITORY, graph=(app, dependency), expected_failure=True))
    return {'checks': checks, 'archive_sha256': {p.path: digests[p] for p in packages},
            'selected': {p.path: digests[p] for p in (app, dependency)},
            'fallback': {p.path: digests[p] for p in (app, legacy_dependency)}}
