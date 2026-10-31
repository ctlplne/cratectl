#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Own one advisory-lock session in an isolated, loopback cratectl test database."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
KIND = 'cratectl-owned-advisory-barrier-v1'


def environment():
    env = dict(os.environ)
    if (env.get('PGHOST') != '127.0.0.1' or env.get('PGPORT') != '35432'
            or not re.fullmatch(r'cratectl_[a-z0-9_]{1,48}', env.get('PGDATABASE', ''))
            or not re.fullmatch(r'cratectl_[a-z0-9_]{1,40}', env.get('PGUSER', ''))):
        raise ValueError('Use an isolated owned cratectl database on loopback 35432')
    return env


def state_path(value):
    path = Path(value)
    if path.is_symlink():
        raise ValueError('Timing state must be a private regular file')
    path = path.resolve()
    if not path.is_relative_to(ROOT / '.private') or not path.parent.is_dir():
        raise ValueError('Keep timing ownership state under the existing private fixture')
    return path


def save(path, state, initial=False):
    data = (json.dumps(state, indent=2) + '\n').encode()
    temporary = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if initial:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def statement(state):
    return f"SELECT pg_advisory_lock({state['lock']}); SELECT pg_sleep({state['seconds']})"


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def query(env, sql):
    control = dict(env, PGAPPNAME='cratectl-timing-control',
                   PGOPTIONS='-c statement_timeout=10000 -c lock_timeout=5000')
    result = subprocess.run([str(PSQL), '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql],
                            env=control, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=12)
    if result.returncode or len(result.stdout) > 16384:
        raise RuntimeError('Owned timing control failed; inspect the retained fixture')
    return result.stdout.strip()


def find(env, state):
    rows = json.loads(query(env, "SELECT COALESCE(json_agg(json_build_object("
        "'pid',a.pid,'backend_start',a.backend_start,'query',a.query,"
        "'held',EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory'"
        f" AND l.objid={state['lock']} AND l.classid=0 AND l.objsubid=1 AND l.granted))), '[]')"
        " FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename=current_user"
        " AND a.application_name=" + literal(state['application_name'])))
    if len(rows) > 1 or rows and rows[0]['query'] != statement(state):
        raise RuntimeError('Timing session ownership does not match the recorded helper')
    return rows[0] if rows else None


def load(path, env):
    if path.stat().st_size > 16384 or path.stat().st_mode & 0o777 != 0o600:
        raise ValueError('Invalid private timing state size or permissions')
    state = json.loads(path.read_bytes())
    if (state.get('kind') != KIND or state.get('database') != env['PGDATABASE']
            or state.get('user') != env['PGUSER']
            or not re.fullmatch(r'cratectl-barrier-[a-z0-9-]{1,47}', state.get('application_name', ''))
            or type(state.get('lock')) is not int or not 1 <= state['lock'] <= 2147483647
            or type(state.get('seconds')) is not int or not 1 <= state['seconds'] <= 600):
        raise ValueError('Timing ownership state does not match this isolated fixture')
    return state


def close(path, env):
    state = load(path, env)
    live = find(env, state)
    recorded = state.get('backend')
    if not recorded and state['status'] != 'closed':
        # A killed controller may leave a client still authenticating. Its one
        # loopback connection has a three-second libpq connection timeout.
        if state.get('helper_pid') != os.getpid():
            try:
                os.kill(int(state['helper_pid']), 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError('Stop the timing controller before recovering its startup')
        deadline = time.monotonic() + 3.5
        while live is None and time.monotonic() < deadline:
            time.sleep(.1)
            live = find(env, state)
    if live and recorded and (live['pid'], live['backend_start']) != (
            recorded.get('pid'), recorded.get('backend_start')):
        raise RuntimeError('Timing backend identity changed; no session was terminated')
    terminated = False
    if live:
        state['backend'] = {'pid': live['pid'], 'backend_start': live['backend_start']}
        state['status'] = 'closing'
        save(path, state)
        # Scope every signal to the full recorded identity, never a PID or lock alone.
        response = query(env, "SELECT pg_terminate_backend(pid,5000) FROM pg_stat_activity"
            " WHERE datname=current_database() AND usename=current_user"
            f" AND pid={int(live['pid'])} AND backend_start=" + literal(live['backend_start'])
            + "::timestamptz AND application_name=" + literal(state['application_name'])
            + " AND query=" + literal(statement(state)))
        if response not in ('', 't'):
            raise RuntimeError('Owned timing backend did not terminate within five seconds')
        terminated = response == 't'
    if find(env, state) is not None:
        raise RuntimeError('Owned timing backend remains live after cleanup')
    state['status'] = 'closed'
    state['cleanup'] = {'backend_absent': True, 'termination_wait_ms': 5000,
                        'termination_requested': terminated or
                        state.get('cleanup', {}).get('termination_requested', False)}
    save(path, state)
    return state


def hold(path, env, label, lock, seconds):
    name = label + '-' + str(os.getpid())
    if not re.fullmatch(r'cratectl-barrier-[a-z0-9-]{1,47}', name):
        raise ValueError('Use a bounded unique cratectl-barrier label')
    if not 1 <= lock <= 2147483647 or not 1 <= seconds <= 600:
        raise ValueError('Use a bounded positive lock and sleep duration')
    state = {'kind': KIND, 'status': 'starting', 'application_name': name,
             'database': env['PGDATABASE'], 'user': env['PGUSER'], 'lock': lock,
             'seconds': seconds, 'helper_pid': os.getpid()}
    if find(env, state) is not None:
        raise RuntimeError('Timing application identity already exists')
    save(path, state, initial=True)
    stopping = False

    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    client = None
    try:
        client = subprocess.Popen([str(PSQL), '-X', '-At', '-v', 'ON_ERROR_STOP=1',
            '-c', statement(state)], env=dict(env, PGAPPNAME=name, PGCONNECT_TIMEOUT='3',
                PGOPTIONS='-c statement_timeout=0 -c lock_timeout=0'),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        state['client_pid'] = client.pid
        save(path, state)
        deadline = time.monotonic() + 10
        ready = False
        while not stopping and client.poll() is None:
            live = find(env, state) if not ready else None
            if live and (not state.get('backend') or live['held'] and not ready):
                state['backend'] = {'pid': live['pid'], 'backend_start': live['backend_start']}
                state['status'] = 'ready' if live['held'] else 'waiting'
                ready = live['held']
                save(path, state)
            if not ready and time.monotonic() > deadline:
                raise RuntimeError('Owned timing session did not acquire its lock')
            time.sleep(.1)
        if not stopping and client.returncode != 0:
            raise RuntimeError('Owned timing client exited before requested cleanup')
    finally:
        if client and client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=5)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait(timeout=5)
        close(path, env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['hold', 'close'])
    parser.add_argument('--state', required=True)
    parser.add_argument('--label')
    parser.add_argument('--lock', type=int)
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args()
    os.umask(0o077)
    env = environment()
    path = state_path(args.state)
    if args.action == 'hold':
        if not args.label or args.lock is None:
            parser.error('hold requires --label and --lock')
        hold(path, env, args.label, args.lock, args.seconds)
    else:
        close(path, env)


if __name__ == '__main__':
    main()
