# SPDX-License-Identifier: BUSL-1.1
"""Use stock micromamba to resolve one policy-checked ordered Conda channel."""

from dataclasses import replace
import hashlib
import json
import re

from conda_hosted_fixture import fixtures

GROUP = 'cratectl-conda-stock-group'
FIRST = 'cratectl-conda-stock-first'
LOWER = 'cratectl-conda-stock-lower'


def group_packages(native):
    app, dependency, _, _, foreign = fixtures(native)
    collision = replace(app, payload=b'Owned lower collision bytes.\n')
    lower_only = replace(app, build_number=app.build_number + 1, payload=b'Owned lower-only build bytes.\n')
    return app, dependency, collision, lower_only, foreign


def evaluate_conda_group(native, authority, request, api, consume, restart):
    app, dependency, collision, lower_only, foreign = group_packages(native)
    checks = []
    root = f'{authority}/conda/{GROUP}/'
    management = '/api/v1/repositories/'

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def grant(repo, allowed):
        label = f'conda-group-grant-{repo}-{allowed}'
        api(label, management + repo + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': allowed, 'write': False})

    def get(path, actor='reader'):
        return request(path, actor, repository=GROUP)

    def publish(repo, package):
        data = bodies[package]
        if request(package.path, 'admin', 'PUT', data, repository=repo) != (201, b'', digests[package]):
            raise ValueError('owned Conda group publication did not preserve the exact archive')

    def decide(repo, package, decision):
        api('conda-group-' + repo + '-' + package.filename + '-' + decision, management + repo + '/decisions', 'PUT',
            {'path': package.path, 'digest': digests[package], 'decision': decision})

    def view(subdir, filename='repodata.json'):
        status, body, _ = get(subdir + '/' + filename)
        if status != 200:
            raise ValueError(f'Conda group repodata returned {status}')
        index = json.loads(body)
        source = index['info']['base_url']
        prefix = root + subdir + '/snapshot/'
        if (index['info']['subdir'] != subdir or index['repodata_version'] != 2 or index['packages.conda'] != {}
                or not re.fullmatch(re.escape(prefix) + '[a-f0-9]{64}/', source)):
            raise ValueError('Conda group did not advertise a local native snapshot')
        return source.removeprefix(root), {name: row['sha256'] for name, row in index['packages'].items()}

    bodies = {package: package.archive() for package in (app, dependency, collision, lower_only, foreign)}
    digests = {package: hashlib.sha256(data).hexdigest() for package, data in bodies.items()}
    for member in (FIRST, LOWER):
        api('conda-group-create-' + member, management.rstrip('/'), 'POST',
            {'name': member, 'format': 'conda', 'access': 'restricted', 'require_review': True})
    api('conda-group-create', management.rstrip('/'), 'POST',
        {'name': GROUP, 'format': 'conda', 'mode': 'group', 'access': 'restricted', 'require_review': True,
         'settings': {'members': [FIRST, LOWER]}})
    grant(GROUP, True)
    grant(LOWER, True)
    check('the Conda group requires grants on the endpoint and all owning channels',
          get(native + '/repodata.json')[0] == 403 and get('noarch/repodata.json', 'other')[0] == 404)
    grant(FIRST, True)
    for package in (collision, lower_only, foreign, dependency):
        publish(LOWER, package)
    check('unreviewed retained Conda builds stay out of both current group indexes',
          not view(native)[1] and not view('noarch')[1])
    for package in (collision, lower_only, foreign, dependency):
        decide(LOWER, package, 'allowed')
    old_view, old_rows = view(native)
    noarch_view, portable = view('noarch')
    check('when the preferred source lacks the name the lower source supplies its native and foreign builds',
          old_rows == {p.filename: digests[p] for p in (collision, lower_only)}
          and view(foreign.subdir)[1] == {foreign.filename: digests[foreign]}
          and portable == {dependency.filename: digests[dependency]}
          and get(old_view + collision.filename)[:2] == (200, bodies[collision]))

    publish(FIRST, app)
    check('an unreviewed preferred owner fences the earlier view and all lower platforms for its name',
          not view(native)[1] and not view(foreign.subdir)[1] and get(old_view + collision.filename)[0] == 409)
    decide(FIRST, app, 'allowed')
    native_view, native_rows = view(native)
    check('the approved graph uses two pinned platform snapshots and retains only the current owner builds',
          native_rows == {app.filename: digests[app]}
          and view(native, 'current_repodata.json') == (native_view, native_rows)
          and view('noarch') == (noarch_view, portable) and get(app.path)[0] == 404
          and get(native_view + lower_only.filename)[0] == 404)
    urls = {root + native_view + app.filename, root + noarch_view + dependency.filename}
    check('stock micromamba fetches the exact Conda group dependency graph through the advertised snapshot URLs',
          consume('group-first', repository=GROUP, graph=(app, dependency), expected_urls=urls, download_only=True))
    restart()
    check('fresh stock micromamba links the original inert Conda group archives after restart',
          consume('group-after-restart', repository=GROUP, graph=(app, dependency), expected_urls=urls))
    decide(FIRST, app, 'denied')
    check('current denial removes the native app and refuses the prior exact snapshot URL without fallback',
          not view(native)[1] and view('noarch') == (noarch_view, portable) and get(native_view + app.filename)[0] == 409)
    check('fresh stock micromamba refuses the Conda group graph after the owning digest is denied',
          consume('group-denied', repository=GROUP, graph=(app, dependency), expected_failure=True))
    grant(LOWER, False)
    check('revoking an underlying grant stops Conda group metadata and the previously advertised noarch download',
          get('noarch/repodata.json')[0] == 403 and get(noarch_view + dependency.filename)[0] == 403)
    return {'checks': checks, 'selected': {p.path: digests[p] for p in (app, dependency)},
            'lower_collision_sha256': digests[collision], 'lower_only_sha256': digests[lower_only],
            'foreign_sha256': digests[foreign]}
