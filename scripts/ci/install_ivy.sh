#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail
if test "${GITHUB_ACTIONS:-}" != true || test "${RUNNER_ENVIRONMENT:-}" != github-hosted; then
  echo 'Ivy qualification installation requires an isolated GitHub-hosted runner.' >&2
  exit 1
fi
umask 077
mkdir -p .cache
readarray -t cratectl_ivy_pins < <(python3 - <<'PY'
import json,re
from pathlib import Path
d=json.loads(Path('docs/qualification/jvm-clients.json').read_text())['ivy']
for version,url,digest,expected in [(d['version'],d['distribution'],d['sha512'],'https://downloads.apache.org/ant/ivy/{v}/apache-ivy-{v}-bin.tar.gz'),(d['ant_version'],d['ant_distribution'],d['ant_sha512'],'https://downloads.apache.org/ant/binaries/apache-ant-{v}-bin.tar.gz')]:
 assert re.fullmatch(r'\d+\.\d+\.\d+',version) and re.fullmatch('[0-9a-f]{128}',digest)
 assert url==expected.format(v=version)
 print(url);print(digest)
PY
)
test "${#cratectl_ivy_pins[@]}" -eq 4
for cratectl_pin_index in 0 2; do
  cratectl_archive=".cache/${cratectl_ivy_pins[$cratectl_pin_index]##*/}"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --max-time 300 --max-filesize 67108864 --output "$cratectl_archive" "${cratectl_ivy_pins[$cratectl_pin_index]}"
  printf '%s  %s\n' "${cratectl_ivy_pins[$((cratectl_pin_index+1))]}" "$cratectl_archive" | sha512sum --check --status
  tar -xzf "$cratectl_archive" -C .cache
done
cratectl_ant_directory="${cratectl_archive%-bin.tar.gz}"
chmod 755 "$cratectl_ant_directory/bin/ant"
