#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail
if test "${GITHUB_ACTIONS:-}" != true || test "${RUNNER_ENVIRONMENT:-}" != github-hosted; then
  echo 'SBT qualification installation requires an isolated GitHub-hosted runner.' >&2
  exit 1
fi
cratectl_sbt_series="${1:?Select sbt1 or sbt2}"
umask 077
mkdir -p .cache
readarray -t cratectl_sbt_pins < <(python3 - "$cratectl_sbt_series" <<'PY'
import json,re,sys
from pathlib import Path
series=sys.argv[1]
assert series in ['sbt1','sbt2']
d=json.loads(Path('docs/qualification/jvm-clients.json').read_text())[series]
version=d['version'];expected='https://github.com/sbt/sbt/releases/download/v'+version+'/sbt-'+version+'.tgz'
assert re.fullmatch(r'[12]\.\d{1,3}\.\d{1,3}',version) and d['url']==expected and re.fullmatch('[0-9a-f]{64}',d['sha256'])
assert version.startswith('1.' if series=='sbt1' else '2.')
print(version);print(d['url']);print(d['sha256'])
PY
)
test "${#cratectl_sbt_pins[@]}" -eq 3
cratectl_sbt_archive=".cache/sbt-${cratectl_sbt_pins[0]}.tgz"
cratectl_sbt_directory=".cache/sbt-${cratectl_sbt_pins[0]}"
test ! -e "$cratectl_sbt_directory"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --max-time 300 --max-filesize 67108864 --output "$cratectl_sbt_archive" "${cratectl_sbt_pins[1]}"
printf '%s  %s\n' "${cratectl_sbt_pins[2]}" "$cratectl_sbt_archive" | sha256sum --check --status
mkdir "$cratectl_sbt_directory"
tar -xzf "$cratectl_sbt_archive" --strip-components=1 -C "$cratectl_sbt_directory"
test -f "$cratectl_sbt_directory/bin/sbt-launch.jar"
# The shell/native thin-client wrappers are deliberately never invoked.
