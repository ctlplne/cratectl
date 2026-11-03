#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail
if test "${GITHUB_ACTIONS:-}" != true || test "${RUNNER_ENVIRONMENT:-}" != github-hosted; then
  echo 'Gradle qualification installation requires an isolated GitHub-hosted runner.' >&2
  exit 1
fi
umask 077
mkdir -p .cache
readarray -t cratectl_gradle_pin < <(python3 - <<'PY'
import json,re
from pathlib import Path
d=json.loads(Path('docs/qualification/jvm-clients.json').read_text())['gradle']
assert re.fullmatch(r'\d+\.\d+\.\d+',d['version'])
assert re.fullmatch('[0-9a-f]{64}',d['sha256'])
assert d['url']=='https://services.gradle.org/distributions/gradle-'+d['version']+'-bin.zip'
print(d['version']);print(d['sha256']);print(d['url'])
PY
)
test "${#cratectl_gradle_pin[@]}" -eq 3
cratectl_gradle_archive=".cache/gradle-${cratectl_gradle_pin[0]}-bin.zip"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --max-time 300 --max-filesize 201326592 --output "$cratectl_gradle_archive" "${cratectl_gradle_pin[2]}"
printf '%s  %s\n' "${cratectl_gradle_pin[1]}" "$cratectl_gradle_archive" | sha256sum --check --status
unzip -q "$cratectl_gradle_archive" -d .cache
chmod 755 ".cache/gradle-${cratectl_gradle_pin[0]}/bin/gradle"
