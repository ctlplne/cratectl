#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Closed native Cargo evidence for the pinned public source replacement."""
import re

if __package__:
    from .cargo_evidence import validate as validate_controlled
else:
    from cargo_evidence import validate as validate_controlled


INDEX = 'https://index.crates.io'
DOWNLOAD = 'https://static.crates.io/crates'
PACKAGES = {
    'form_urlencoded': ('1.2.1', 'e13624c2627564efccf4934284bdd98cbaa14e79b0b5a141218e507b3a823456'),
    'percent-encoding': ('2.3.1', 'e3148f5046208a5d56bcfc03053e3ca6334e51da8dfb19b6cdc8b306fae3283e'),
}
CHECKS = (
    'the public sparse index advertises the configured crates.io CDN',
    'the official index retains the pinned form_urlencoded checksum',
    'the official index retains the pinned percent-encoding checksum',
    'the pinned root declares the leaf as a required runtime dependency',
    'stock Cargo fetched exactly the pinned public root and leaf archives',
    'the stock lockfile records the real dependency edge and both public checksums',
    'fresh stock Cargo replays the same pinned graph after restart',
    'the independent stock lockfile uses the canonical crates.io source and pinned checksums',
    'the authenticated crates.io replacement fetches both exact archives with an unchanged canonical lockfile',
    'current repository grant gates the stored form_urlencoded archive',
    'current repository grant gates the stored percent-encoding archive',
)
SOURCE_PATHS = ('.github/workflows/cargo-public.yml', 'scripts/cargo_public_fixture.py',
                'scripts/ci/cargo_public_evidence.py')


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def validate(report):
    if type(report) is not dict or report.get('profile') != 'cratectl-native-cargo-public-v1':
        raise ValueError('invalid public Cargo evidence profile')
    controlled = {key: value for key, value in report.items() if key not in ('public_origin', 'public_source_sha256')}
    validate_controlled({**controlled, 'profile': 'cratectl-native-cargo-v1'})
    origin = report.get('public_origin')
    if type(origin) is not dict or set(origin) != {'checks', 'archive_sha256', 'index', 'download_base',
                                                  'lock_sha256', 'canonical_lock_sha256'}:
        raise ValueError('invalid public Cargo result inventory')
    if (origin['index'] != INDEX or origin['download_base'] != DOWNLOAD or origin['checks'] != list(CHECKS)
            or origin['archive_sha256'] != {f'{name}-{version}.crate': digest for name, (version, digest) in PACKAGES.items()}
            or any(not hash_value(origin[field]) for field in ('lock_sha256', 'canonical_lock_sha256'))
            or origin['lock_sha256'] == origin['canonical_lock_sha256']):
        raise ValueError('invalid public Cargo result or check coverage')
    source = report.get('public_source_sha256')
    if type(source) is not dict or set(source) != set(SOURCE_PATHS) or any(not hash_value(value) for value in source.values()):
        raise ValueError('invalid public Cargo source digest inventory')
    return report
