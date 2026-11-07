#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail

if test "${GITHUB_ACTIONS:-}" != true || test "${RUNNER_ENVIRONMENT:-}" != github-hosted; then
  echo 'This bootstrap requires an isolated GitHub-hosted runner.' >&2
  exit 1
fi
: "${CRATECTL_CI_POSTGRES_CONTAINER_ID:?Pass the owned workflow service container ID}"
if [[ ! "$CRATECTL_CI_POSTGRES_CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]; then
  echo 'The CI PostgreSQL service container identity is invalid.' >&2
  exit 1
fi

# Run only in an isolated GitHub-hosted Linux runner. The fixed paths are the
# existing native qualification tools' paths; all downloaded bytes are checked.
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
docker inspect --type container --format '{{json .NetworkSettings.Ports}}' "$CRATECTL_CI_POSTGRES_CONTAINER_ID" | python3 scripts/ci/check_postgres_binding.py
# These fixed service ports must not be chosen as automatic outbound client
# ports while a fixture listener is between lifetimes. Preserve inherited
# reservations and prove the kernel behavior in fresh child namespaces first.
sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT,RUNNER_OS,CRATECTL_CI_POSTGRES_CONTAINER_ID python3 scripts/ci/prepare_owned_ports.py
client_set="${CRATECTL_CI_CLIENT_SET:-all}"
case "$client_set" in all|oci|jvm|go|upgrades) ;; *) echo 'Unknown CI client set' >&2; exit 1 ;; esac
architecture="$(dpkg --print-architecture)"
umask 077
mkdir -p .cache/go/bin .cache/clients/bin .cache/bin .private
chmod 700 .private
ln -s "$(command -v go)" .cache/go/bin/go
ln -s "$(command -v python)" .cache/clients/bin/python
if test "$client_set" = all || test "$client_set" = jvm; then
  mkdir -p .cache/jdk-21.0.13+9/Contents
  ln -s "$JAVA_HOME" .cache/jdk-21.0.13+9/Contents/Home
fi
if test "$client_set" = all || test "$client_set" = upgrades; then
  case "$architecture" in
    amd64) oras_sha=66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0 ;;
    arm64) oras_sha=b84269e78dfc2d5329a4aab373da3200de95e6c138338cf6c66c10c0a3f248c1 ;;
    *) printf 'Unsupported CI architecture: %s\n' "$architecture" >&2; exit 1 ;;
  esac
  oras_archive="oras_1.3.6_linux_${architecture}.tar.gz"
  python3 scripts/ci/fetch_archive.py --archive "$oras_archive" --url "https://github.com/oras-project/oras/releases/download/v1.3.6/$oras_archive" --sha256 "$oras_sha" --max-bytes 33554432
  printf '%s  %s\n' "$oras_sha" ".cache/$oras_archive" | sha256sum --check --status
  tar -xzf ".cache/$oras_archive" -C .cache/bin oras
  chmod 755 .cache/bin/oras
fi

# Controlled upgrades need stock npm (setup-node) and ORAS, not JVM/PyPI tools.
if test "$client_set" = all; then
  bash scripts/ci/install_maven.sh

  python -m pip install --disable-pip-version-check twine==7.0.0 build==1.3.0
fi
sudo apt-get update -qq
sudo apt-get install --yes --quiet postgresql-client-16
mkdir -p .cache/postgresql-16.15-install/bin
ln -s "$(command -v psql)" .cache/postgresql-16.15-install/bin/psql

# Generate credentials inside this disposable runner. Test scripts require a
# complete DSN; the values never appear in the repository or workflow source.
: "${GITHUB_ENV:?Run this bootstrap in GitHub Actions}"
owner_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
printf '::add-mask::%s\n::add-mask::%s\n' "$owner_password" "$runtime_password"
export CRATECTL_OWNER_DSN="postgres://cratectl_owner:${owner_password}@127.0.0.1:35432/cratectl?sslmode=disable"
export CRATECTL_DSN="postgres://cratectl_app:${runtime_password}@127.0.0.1:35432/cratectl?sslmode=disable"
printf 'CRATECTL_OWNER_DSN=%s\nCRATECTL_DSN=%s\n' "$CRATECTL_OWNER_DSN" "$CRATECTL_DSN" >> "$GITHUB_ENV"
psql -h 127.0.0.1 -p 35432 -U cratectl_owner -d cratectl -v ON_ERROR_STOP=1 -c "ALTER ROLE cratectl_owner PASSWORD '$owner_password'"

cat > .private/ci-db.json <<EOF
{"owner":"$CRATECTL_OWNER_DSN","runtime":"$CRATECTL_DSN"}
EOF
chmod 600 .private/ci-db.json

make build BINDIR=.cache/ci-build
.cache/ci-build/cratectld migrate
psql -h 127.0.0.1 -p 35432 -U cratectl_owner -d cratectl -v ON_ERROR_STOP=1 -c "ALTER ROLE cratectl_app LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD '$runtime_password'"
for tenant in test-a test-b; do
  .cache/ci-build/cratectld provision --tenant "$tenant" --actor operator --role admin --token-file ".private/ci-$tenant.token"
done
.cache/ci-build/cratectld migrate --plan | python scripts/ci/check_schema_plan.py
uname -sm
go version
python --version
if test "$client_set" = all; then
  node --version
  npm --version
  java -version
  .cache/apache-maven-3.10.0/bin/mvn -version
  .cache/bin/oras version
fi
.cache/postgresql-16.15-install/bin/psql --version
printf 'Real PostgreSQL and native binaries are ready for the %s client set on this %s runner.\n' "$client_set" "$architecture"
