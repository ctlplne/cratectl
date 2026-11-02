# SPDX-License-Identifier: BUSL-1.1
"""Explicit schema target shared by native upgrade qualification fixtures.

Advance this only with an appended migration and frozen-receipt evidence. Never
derive the expected version from the database under test.
"""

import os
from pathlib import Path

CURRENT_SCHEMA = 11


def validate_historical_build(metadata, source, goos, goarch):
    """Reject stale, dirty or cross-built historical qualification artifacts."""
    settings = {}
    for line in metadata.splitlines():
        fields = line.strip().split('\t')
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            settings[key] = value
    expected = {'vcs': 'git', 'vcs.revision': source, 'vcs.modified': 'false', 'GOOS': goos, 'GOARCH': goarch}
    if any(settings.get(key) != value for key, value in expected.items()):
        raise ValueError('Historical build does not match its clean native source identity')
    return settings


def candidate_binary_directory(override=None):
    """Select owned qualification artifacts without replacing the active bin."""
    root = Path(__file__).resolve().parents[1]
    folder = Path(override or os.environ.get('CRATECTL_QUALIFICATION_BIN_DIR') or root / 'bin')
    if not folder.is_absolute():
        folder = root / folder
    folder = folder.resolve()
    if not folder.is_relative_to(root):
        raise ValueError('Qualification binaries must stay inside the cratectl workspace')
    return folder


def candidate_artifact_names():
    root = Path(__file__).resolve().parents[1]
    return [str((candidate_binary_directory() / name).relative_to(root)) for name in ['cratectld', 'cratectl']]
