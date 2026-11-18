#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Replay hosted npm search using inert packages and the stock client."""
import json


REPOSITORY = 'cratectl-npm-search'
NAME = 'cratectl-search-lib'
SCOPED = '@cratectl/cratectl-search-extra'


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
    global_config = work / 'npm-search-global.npmrc'
    global_config.touch()
    clients = {}
    for label, config in [('writer', None), ('reader', reader_config), ('second', other_config)]:
        rc = work / f'npm-search-{label}.npmrc'
        cli('npm-search-config-' + label, 'npm-config', '--repository', REPOSITORY, '--output', rc, config=config)
        clients[label] = dict(environment, NPM_CONFIG_USERCONFIG=str(rc), NPM_CONFIG_GLOBALCONFIG=str(global_config),
                              NPM_CONFIG_CACHE=str(work / f'npm-search-cache-{label}'), NPM_CONFIG_AUDIT='false',
                              NPM_CONFIG_FUND='false', NPM_CONFIG_IGNORE_SCRIPTS='true')
    consumer = work / 'npm-search-consumer'
    consumer.mkdir()

    def publish(label, name, version, description, role):
        source = work / ('npm-search-package-' + label)
        source.mkdir()
        (source / 'package.json').write_text(json.dumps(
            {'name': name, 'version': version, 'description': description, 'license': 'MIT', 'files': ['payload.txt']}))
        (source / 'payload.txt').write_text(description + '\n')
        child = clients[role]
        _, output = call('npm-search-pack-' + label, 'npm', 'pack', '--ignore-scripts', '--json', cwd=source, environment=child)
        archive = source / json.loads(output)[0]['filename']
        call('npm-search-publish-' + label, 'npm', 'publish', '--ignore-scripts', archive, cwd=source, environment=child)
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
