#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Install exact candidate executables inside a native, network-isolated Linux target."""

import argparse
from functools import partial
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import stat
import sys
import tempfile

from linux_install_evidence import CHECKS, DRIVER_PATHS, IMAGE, SOURCE_PATHS, matches, validate

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from bounded_client import run_owned_client
from package_linux import BINARIES, digest
from verify_linux_candidate import require

MACHINES = {'amd64': ('x86_64', 'X64'), 'arm64': ('aarch64', 'ARM64')}


def command(*args, timeout=40, refusal=None, cwd=ROOT):
    argv = [str(item) for item in args]
    code, output = run_owned_client(argv, cwd, os.environ, timeout=timeout, output_limit=128 << 10)
    if refusal is None:
        require(code == 0, 'command failed: ' + ' '.join(argv[:3]) + '\n' + output)
    else:
        require(code == 1 and refusal in output, 'missing installer refusal: ' + refusal)
    return output.strip()


def archive(directory, architecture):
    return directory / f'cratectl-linux-{architecture}.tar.gz'


def only_loopback():
    devices = Path('/sys/class/net')
    flags = {name: int((devices / name / 'flags').read_text(), 16) for _, name in socket.if_nameindex()}
    # Some kernels expose default, administratively down tunnel devices in
    # every network namespace. Check IFF_UP and both kernel route tables.
    active = {name for name, value in flags.items() if value & 0x1}
    ipv4 = Path('/proc/net/route').read_text().splitlines()[1:]
    ipv6 = Path('/proc/net/ipv6_route').read_text().splitlines()
    return (active == {'lo'} and flags['lo'] & 0x8 != 0
            and all(row.split()[0] == 'lo' for row in ipv4)
            and all(row.split()[-1] == 'lo' for row in ipv6))


def qualify_inside(architecture, candidate, expected, other_digest):
    machine, runner = MACHINES[architecture]
    checks = []

    def check(name, condition):
        require(condition, 'isolated Linux installation check failed: ' + name)
        checks.append(name)

    check('nonroot-native-linux', os.geteuid() == 65532 and platform.system() == 'Linux'
          and platform.machine() == machine)
    check('only-loopback', only_loopback())
    with tempfile.TemporaryDirectory(prefix='cratectl-linux-install-') as folder:
        target = Path(folder)
        target_command = partial(command, cwd=target)
        safe = target / 'installations'
        safe.mkdir(mode=0o700)
        check('empty-target', not list(safe.iterdir()))
        other = 'arm64' if architecture == 'amd64' else 'amd64'
        base = (sys.executable, ROOT / 'scripts/install_linux_candidate.py')
        installer = (*base, archive(ROOT, architecture), '--directory', safe, '--sha256')
        installed = safe / f'cratectl-{candidate}-{architecture}'
        observed = target_command(*installer, expected)
        check('trusted-install', Path(observed) == installed and list(safe.iterdir()) == [installed])
        files = {'manifest.json': 0o644, **dict.fromkeys(BINARIES, 0o755)}
        manifest = json.loads((installed / 'manifest.json').read_text())
        check('manifest-and-modes', manifest['candidate'] == candidate
              and manifest['platform'] == 'linux/' + architecture
              and {path.name for path in installed.iterdir()} == set(files)
              and all(stat.S_ISREG((installed / name).lstat().st_mode)
                      and stat.S_IMODE((installed / name).stat().st_mode) == mode
                      for name, mode in files.items()))
        hashes = {name: digest(installed / name) for name in BINARIES}
        check('installed-digests', all(hashes[name] == manifest['binaries'][name]['sha256'] for name in BINARIES))
        cli_help = target_command(installed / 'cratectl', 'npm-config', '--help', refusal='flag: help requested')
        check('cli-execution', 'Usage of npm-config:' in cli_help and '-repository' in cli_help)
        server_help = target_command(installed / 'cratectld', 'migrate', '--help', refusal='flag: help requested')
        check('server-execution', 'Usage of migrate:' in server_help and '-plan' in server_help)

        empty = target / 'refusals'
        empty.mkdir(mode=0o700)
        wrong = ('0' if expected[0] != '0' else '1') + expected[1:]
        target_command(*base, archive(ROOT, architecture), '--directory', empty, '--sha256', wrong,
                       refusal='compressed archive SHA-256 differs')
        check('bad-digest-cleanup', not list(empty.iterdir()))
        target_command(*base, archive(ROOT, other), '--directory', empty, '--sha256', other_digest,
                       refusal='archive platform differs')
        check('other-platform-cleanup', not list(empty.iterdir()))
        target_command(*installer, expected, refusal='this candidate installation already exists')
        check('existing-candidate-preserved', list(safe.iterdir()) == [installed]
              and all(digest(installed / name) == hashes[name] for name in BINARIES))
        alias = target / 'alias'
        alias.symlink_to(empty, target_is_directory=True)
        target_command(*base, archive(ROOT, architecture), '--directory', alias, '--sha256', expected,
                       refusal='Linux candidate installation failed:')
        empty.chmod(0o755)
        target_command(*base, archive(ROOT, architecture), '--directory', empty, '--sha256', expected,
                       refusal='installation directory must be owned by the caller with mode 0700')
        check('unsafe-target-refused', not list(empty.iterdir()))
    return {'runner_arch': runner, 'checks': checks, 'binary_sha256': hashes}


def replay(architecture):
    require(not command('git', 'status', '--porcelain'), 'build the Linux installation fixture from a clean commit')
    candidate = command('git', 'rev-parse', 'HEAD')
    require(matches(candidate, '[a-f0-9]{40}'), 'invalid Linux installation candidate')
    machine, _ = MACHINES[architecture]
    require(platform.machine() in (machine, architecture), 'qualification requires a matching host architecture')
    endpoint = command('docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
    require(endpoint.startswith('unix://') and os.environ.get('DOCKER_HOST', 'unix://').startswith('unix://'),
            'qualification requires the local Docker Unix socket')
    engine = command('docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}')
    require(engine in ('linux/' + machine, 'linux/' + architecture), 'qualification requires a matching Linux engine')
    command(sys.executable, ROOT / 'scripts/package_linux.py', timeout=590)

    cache = ROOT / '.cache'
    source_dir = cache / 'cratectl-linux-candidates' / candidate
    with tempfile.TemporaryDirectory(prefix='cratectl-linux-install-', dir=cache) as folder:
        inputs = Path(folder)
        remote_user = 65532
        inputs.chmod(0o755)
        for name in DRIVER_PATHS:
            destination = inputs / name
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            # The host may set umask 077. Only inert source and reviewed archives
            # enter this temporary, read-only container input.
            destination.parent.chmod(0o755)
            destination.parent.parent.chmod(0o755)
            shutil.copyfile(ROOT / name, destination)
            destination.chmod(0o644)
        hashes = {}
        for arch in MACHINES:
            path = archive(inputs, arch)
            shutil.copyfile(archive(source_dir, arch), path)
            path.chmod(0o644)
            hashes[arch] = digest(path)
        other = 'arm64' if architecture == 'amd64' else 'amd64'
        container = 'cratectl-linux-install-' + secrets.token_hex(6)
        try:
            result = command('docker', 'run', '--rm', '--pull=never', '--platform=linux/' + architecture,
                             '--name=' + container, '--network=none', '--read-only',
                             '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64',
                             f'--user={remote_user}:{remote_user}', '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=384m,mode=1777',
                             '--mount=type=bind,source=' + str(inputs) + ',destination=/input,readonly',
                             IMAGE, 'python3', '-B', '/input/scripts/ci/qualify_linux_install.py',
                             architecture, '--inside', candidate, hashes[architecture], hashes[other], timeout=180)
        except (OSError, RuntimeError, ValueError):
            # A killed docker client may leave its container running.
            run_owned_client(['docker', 'rm', '-f', container], ROOT, os.environ, timeout=20, output_limit=32 << 10)
            raise
    report = {**json.loads(result), 'schema': 1, 'profile': 'cratectl-native-linux-install-v1',
              'candidate': candidate, 'run_id': os.environ.get('GITHUB_RUN_ID'), 'runner_os': 'Linux',
              'status': 'passed', 'source_dirty': False, 'python_image': IMAGE,
              'archive_sha256': hashes[architecture], 'source_sha256': {path: digest(ROOT / path) for path in SOURCE_PATHS},
              'goal_complete': False, 'broad_readiness': False}
    validate(report, local=report['run_id'] is None)
    output = cache / 'ci-linux-install.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(CHECKS)} scoped native Linux installation checks')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=MACHINES)
    parser.add_argument('--inside', nargs=3, metavar=('CANDIDATE', 'DIGEST', 'OTHER_DIGEST'))
    args = parser.parse_args()
    try:
        if args.inside:
            print(json.dumps(qualify_inside(args.architecture, *args.inside)))
        else:
            replay(args.architecture)
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__':
    main()
