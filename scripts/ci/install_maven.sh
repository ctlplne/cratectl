#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail
if test "${GITHUB_ACTIONS:-}" != true || test "${RUNNER_ENVIRONMENT:-}" != github-hosted; then
  echo 'Maven qualification installation requires an isolated GitHub-hosted runner.' >&2
  exit 1
fi
umask 077
mkdir -p .cache
maven_sha="$(python3 - <<'PY'
import json,re
from pathlib import Path
p=json.loads(Path('docs/qualification/jvm-clients.json').read_text())['maven']
assert p['version']=='3.10.0' and re.fullmatch('[0-9a-f]{128}',p['sha512'])
assert p['distribution']=='https://downloads.apache.org/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz'
assert p['archive_distribution']=='https://archive.apache.org/dist/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz'
print(p['sha512'])
PY
)"
maven_archive=.cache/apache-maven-3.10.0-bin.tar.gz
maven_downloaded=false
for maven_base in https://downloads.apache.org/maven/maven-3/3.10.0/binaries https://archive.apache.org/dist/maven/maven-3/3.10.0/binaries; do
  if curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --max-filesize 33554432 --output "$maven_archive.part" "$maven_base/apache-maven-3.10.0-bin.tar.gz"; then
    # A completed but incorrect download fails immediately. Never hide a digest
    # mismatch by fetching different bytes from another host.
    printf '%s  %s\n' "$maven_sha" "$maven_archive.part" | sha512sum --check --status
    mv "$maven_archive.part" "$maven_archive"
    maven_downloaded=true
    break
  fi
  rm -f "$maven_archive.part"
  printf 'Maven tool transfer failed from approved source: %s\n' "$maven_base" >&2
done
if test "$maven_downloaded" != true; then
  echo 'Both bounded, approved Maven tool transfers failed; native qualification did not run.' >&2
  exit 1
fi
tar -xzf "$maven_archive" -C .cache
