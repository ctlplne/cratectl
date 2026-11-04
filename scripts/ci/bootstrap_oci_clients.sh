#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_OS:-}" = Linux
umask 077
mkdir -p .cache/bin
architecture="$(dpkg --print-architecture)"
case "$architecture" in
  amd64)
    helm_sha=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
    ;;
  arm64)
    helm_sha=8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88
    ;;
  *) echo 'OCI client qualification requires native Linux amd64 or arm64' >&2; exit 1 ;;
esac
archive="helm-v4.3.1-linux-$architecture.tar.gz"
python3 scripts/ci/fetch_archive.py --archive "$archive" --url "https://get.helm.sh/$archive" --sha256 "$helm_sha" --max-bytes 67108864
printf '%s  %s\n' "$helm_sha" ".cache/$archive" | sha256sum --check --status
tar -xzf ".cache/$archive" -C .cache/bin --strip-components=1 "linux-$architecture/helm"
chmod 755 .cache/bin/helm
sudo apt-get update -qq
podman --version
test "$(podman --version)" = 'podman version 4.9.3'
dpkg-query --show --showformat='Podman package: ${Version}; architecture: ${Architecture}\n' podman
sudo apt-get install --yes --quiet --no-install-recommends crun
docker version
docker buildx version
podman --version
.cache/bin/helm version --short
