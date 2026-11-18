#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Replay hosted npm search using inert packages and the stock client."""
import base64
import hashlib
import json

from cargo_proxy_fixture import origin_server


REPOSITORY = 'cratectl-npm-search'
NAME = 'cratectl-search-lib'
SCOPED = '@cratectl/cratectl-search-extra'


def npm_client(work, label, repo, config, environment, cli):
    rc = work / f'npm-search-{label}.npmrc'
    cli('npm-search-config-' + label, 'npm-config', '--repository', repo, '--output', rc, config=config)
    global_config = work / 'npm-search-global.npmrc'
    global_config.touch()
    return dict(environment, NPM_CONFIG_USERCONFIG=str(rc), NPM_CONFIG_GLOBALCONFIG=str(global_config),
                NPM_CONFIG_CACHE=str(work / f'npm-search-cache-{label}'), NPM_CONFIG_AUDIT='false',
                NPM_CONFIG_FUND='false', NPM_CONFIG_IGNORE_SCRIPTS='true')


def npm_archive(work, label, name, version, description, call, environment):
    source = work / ('npm-search-package-' + label)
    source.mkdir()
    (source / 'package.json').write_text(json.dumps(
        {'name': name, 'version': version, 'description': description, 'license': 'MIT', 'files': ['payload.txt']}))
    (source / 'payload.txt').write_text(description + '\n')
    _, output = call('npm-search-pack-' + label, 'npm', 'pack', '--ignore-scripts', '--json', cwd=source, environment=environment)
    return source / json.loads(output)[0]['filename']


def evaluate_search(work, environment, call, cli, api, restart, sha):
    checks = []

    def check(label, passed):
        if not passed:
            raise ValueError(label)
        checks.append(label)

    management = '/api/v1/repositories/' + REPOSITORY
    reader_config, other_config = work / 'reader.json', work / 'other.json'
    for label, config in [('main', None), ('second', other_config)]:
        api('npm-search-create-' + label, '/api/v1/repositories', 'POST',
            {'name': REPOSITORY, 'format': 'npm', 'access': 'restricted', 'require_review': True}, config=config)
    grant = {'actor': 'cratectl-reader', 'read': True, 'write': False}
    api('npm-search-grant', management + '/grants', 'PUT', grant)
    clients = {label: npm_client(work, label, REPOSITORY, config, environment, cli)
               for label, config in [('writer', None), ('reader', reader_config), ('second', other_config)]}
    consumer = work / 'npm-search-consumer'
    consumer.mkdir()

    def publish(label, name, version, description, role):
        child = clients[role]
        archive = npm_archive(work, label, name, version, description, call, child)
        call('npm-search-publish-' + label, 'npm', 'publish', '--ignore-scripts', archive, cwd=archive.parent, environment=child)
        return sha(archive)

    old_digest = publish('old', NAME, '2.0.0', 'First tenant stable package', 'writer')
    new_digest = publish('new', NAME, '10.0.0', 'First tenant newer package', 'writer')
    scoped_digest = publish('scoped', SCOPED, '1.0.0', 'First tenant scoped package', 'writer')
    other_digest = publish('second', NAME, '2.0.0', 'Second tenant stable package', 'second')

    def search(label, query, role='reader', *options):
        _, output = call('npm-search-' + label, 'npm', 'search', '--json', '--prefer-online', *options, query,
                         cwd=consumer, environment=clients[role])
        return [(item['name'], item['version'], item['description']) for item in json.loads(output)]

    def approval(label, name, version, digest, config=None):
        reference = {'path': f'{name}/-/{name}-{version}.tgz', 'digest': digest}
        api('npm-search-approve-' + label, management + '/decisions', 'PUT', {**reference, 'decision': 'allowed'}, config=config)
        return reference

    check('unassessed versions are absent from stock npm search', search('pending', 'cratectl-search') == [])
    old_reference = approval('old', NAME, '2.0.0', old_digest)
    approval('scoped', SCOPED, '1.0.0', scoped_digest)
    approval('second', NAME, '2.0.0', other_digest, config=other_config)
    old = (NAME, '2.0.0', 'First tenant stable package')
    newer = (NAME, '10.0.0', 'First tenant newer package')
    scoped = (SCOPED, '1.0.0', 'First tenant scoped package')
    check('stock npm returns approved scoped and unscoped names while hiding the pending latest version',
          search('approved', 'cratectl-search') == [old, scoped])
    check('the npm search limit returns only the highest ranked package', search('one', 'cratectl-search', 'reader', '--searchlimit=1') == [old])
    check('the second tenant sees its own description at the same coordinate',
          search('second-tenant', NAME, 'second') == [(NAME, '2.0.0', 'Second tenant stable package')])
    approval('new', NAME, '10.0.0', new_digest)
    check('approving the latest version replaces the search projection',
          search('newest', NAME) == [newer])
    call('npm-search-tag-old', 'npm', 'dist-tag', 'add', NAME + '@2.0.0', 'latest',
         cwd=consumer, environment=clients['writer'])
    check('stock npm searches the current latest tag even when it points at an earlier allowed version',
          search('tagged', NAME) == [old])

    lifecycle = management + '/artifacts/lifecycle'
    api('npm-search-retire', lifecycle, 'PUT', {**old_reference, 'action': 'delete', 'expected_revision': 0,
                                               'reason': 'Verify updated search after retaining a version'})
    check('retirement removes the tagged version from stock search', search('retired', NAME) == [newer])
    api('npm-search-restore', lifecycle, 'PUT', {**old_reference, 'action': 'restore', 'expected_revision': 1,
                                                'reason': 'Restore verified original bytes'})
    restart()
    _, output = call('npm-search-original-archive', 'npm', 'pack', '--ignore-scripts', '--json', NAME + '@2.0.0',
                     cwd=consumer, environment=clients['reader'])
    archive = consumer / json.loads(output)[0]['filename']
    check('stock npm sees the restored tag and exact original archive after restart',
          search('restored', NAME) == [old] and sha(archive) == old_digest)
    api('npm-search-revoke', management + '/grants', 'PUT', {**grant, 'read': False})
    _, failure = call('npm-search-revoked-client', 'npm', 'search', '--json', '--prefer-online', NAME,
                      cwd=consumer, environment=clients['reader'], status=1)
    check('an existing stock npm client loses search access after grant revocation', 'E403' in failure)
    return {'checks': checks, 'archive_sha256': [old_digest, new_digest, scoped_digest, other_digest]}


def evaluate_cached_search(work, environment, call, cli, api, restart, sha):
    checks = []
    lower, proxy, group = ('cratectl-npm-search-' + part for part in ('lower', 'proxy', 'group'))
    path = '/cratectl-npm-search-origin/'
    origin = 'http://[::1]:38443' + path
    name, fallback, version = 'cratectl-search-copy', 'cratectl-search-fallback', '1.0.0'
    preferred_description, lower_description = 'Preferred exact npm archive', 'Lower hosted npm archive'
    reader = work / 'reader.json'

    def check(label, passed):
        if not passed:
            raise ValueError(label)
        checks.append(label)

    def management(repo):
        return '/api/v1/repositories/' + repo

    def grant(repo, label, allowed=True):
        api('npm-cache-search-grant-' + label, management(repo) + '/grants', 'PUT',
            {'actor': 'cratectl-reader', 'read': allowed, 'write': False})

    for repo, mode, review, settings in (
            (lower, 'hosted', True, {}),
            (proxy, 'proxy', False, {'upstream': {'url': origin, 'networks': ['::1/128']},
                                    'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'stale_seconds': 0}}),
            (group, 'group', True, {'members': [proxy, lower]})):
        api('npm-cache-search-create-' + mode, '/api/v1/repositories', 'POST',
            {'name': repo, 'format': 'npm', 'mode': mode, 'access': 'restricted', 'require_review': review, 'settings': settings})
        grant(repo, mode)
    writer = npm_client(work, 'cache-writer', lower, None, environment, cli)
    proxy_client = npm_client(work, 'cache-proxy', proxy, reader, environment, cli)
    group_client = npm_client(work, 'cache-group', group, reader, environment, cli)
    consumer = work / 'npm-search-cached-consumer'
    consumer.mkdir()

    def approval(repo, label, coordinate, digest):
        items = api('npm-cache-search-inspect-' + label, management(repo) + '/artifacts')['items']
        archive, = [item for item in items if item.get('digest') == digest and item['metadata'].get('name') == coordinate]
        reference = {'path': archive['path'], 'digest': digest}
        api('npm-cache-search-approve-' + label, management(repo) + '/decisions', 'PUT', {**reference, 'decision': 'allowed'})
        return reference

    for label, coordinate in [('lower-copy', name), ('lower-only', fallback)]:
        archive = npm_archive(work, label, coordinate, version, lower_description, call, writer)
        call('npm-search-publish-' + label, 'npm', 'publish', '--ignore-scripts', archive, cwd=archive.parent, environment=writer)
        approval(lower, label, coordinate, sha(archive))
    archive = npm_archive(work, 'preferred', name, version, preferred_description, call, writer)
    package_bytes = archive.read_bytes()
    archive_path = name + '/-/' + archive.name
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(package_bytes).digest()).decode()
    document = {'name': name, 'dist-tags': {'latest': version}, 'versions': {version: {
        'name': name, 'version': version, 'description': 'Unmaterialized origin description',
        'dist': {'tarball': origin + archive_path, 'integrity': integrity},
    }}}
    content = {path + name: json.dumps(document).encode(), path + archive_path: package_bytes}

    def npm(label, client, *arguments):
        return call('npm-cache-search-' + label, 'npm', *arguments, cwd=consumer, environment=client)[1]

    def search(label, client, query):
        return [(item['version'], item['description']) for item in
                json.loads(npm(label, client, 'search', '--prefer-online', '--json', query))]

    with origin_server({'index': '', 'download': ''}, content) as (requests, lock, _, _, _):
        check('stock npm cached search makes no network fill and fences an unknown preferred source',
              search('proxy-cold', proxy_client, name) == search('group-cold', group_client, name) == [] and not requests)
        npm('warm-index', proxy_client, 'view', name, 'version', '--json')
        check('stock search omits a catalog-only proxy version and its lower duplicate',
              search('proxy-catalog-only', proxy_client, name) == search('group-catalog-only', group_client, name) == [])
        packed = json.loads(npm('fetch-bytes', proxy_client, 'pack', '--ignore-scripts', '--json', name + '@' + version))[0]['filename']
        expected = [(version, preferred_description)]
        check('stock proxy search uses the exact fetched archive description',
              sha(consumer / packed) == sha(archive) and search('proxy-cached', proxy_client, name) == expected)
        check('mixed group review fences the lower duplicate while the preferred bytes await approval',
              search('group-pending', group_client, name) == [])
        approval(proxy, 'preferred', name, sha(archive))
        check('stock group search selects the approved preferred proxy bytes',
              search('group-approved', group_client, name) == expected)
        npm('negative-authority', group_client, 'view', fallback, 'version', '--json')
        check('current proxy absence admits the hosted package in stock group search',
              search('negative-search', group_client, fallback) == [(version, lower_description)])
        restart()
        with lock:
            before = len(requests)
        found = search('restart', group_client, name)
        with lock:
            after = len(requests)
        check('stock search replays the same source after restart without upstream requests', found == expected and before == after)
        api('npm-cache-search-expire', management(proxy) + '/cache', 'PUT', {'path': 'npm-catalog/' + name})
        check('invalidating the preferred catalog hides the cached result and its lower duplicate',
              search('proxy-expired', proxy_client, name) == search('group-expired', group_client, name) == [])
        grant(proxy, 'revoke', allowed=False)
        check('revoking a selected member grant hides the cached and lower group results',
              search('revoked-member', group_client, fallback) == [])
    return {'checks': checks, 'preferred_archive_sha256': sha(archive)}
