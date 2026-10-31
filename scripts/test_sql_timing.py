#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Real PostgreSQL regression tests; missing owned configuration is a failure."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
HELPER = ROOT / 'scripts/sql_timing.py'


class TimingSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.umask(0o077)
        owner = urllib.parse.urlsplit(os.environ['CRATECTL_OWNER_DSN'])
        if owner.hostname != '127.0.0.1' or owner.port != 35432:
            raise ValueError('Use the project-owned loopback PostgreSQL fixture')
        cls.run_id = uuid.uuid4().hex[:10]
        cls.area = ROOT / '.private/timing-helper-tests' / cls.run_id
        cls.area.mkdir(parents=True, mode=0o700)
        cls.env = dict(os.environ, PGHOST=owner.hostname, PGPORT=str(owner.port),
                       PGUSER=urllib.parse.unquote(owner.username),
                       PGPASSWORD=urllib.parse.unquote(owner.password),
                       PGDATABASE=owner.path.lstrip('/'))
        database = 'cratectl_timing_' + cls.run_id
        cls.sql('CREATE DATABASE ' + database)
        cls.env['PGDATABASE'] = database
        print('Retained timing regression fixture: ' + str(cls.area), flush=True)

    @classmethod
    def sql(cls, statement):
        return subprocess.check_output([str(PSQL), '-X', '-At', '-v',
            'ON_ERROR_STOP=1', '-c', statement], env=cls.env, text=True, timeout=15).strip()

    def setUp(self):
        self.holders = []
        self.number = 0

    def tearDown(self):
        for child, path in reversed(self.holders):
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            if path.exists():
                self.command('close', path, ok=True)

    def command(self, action, path, extra=(), env=None, ok=True):
        result = subprocess.run([sys.executable, str(HELPER), action, '--state', str(path),
            *extra], env=env or self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=15)
        log = self.area / (self.id().split('.')[-1] + '-command-' + uuid.uuid4().hex[:8] + '.log')
        log.write_text(result.stdout)
        self.assertEqual(result.returncode == 0, ok, 'Timing command status; retained log: ' + str(log))
        return result

    def start(self, lock=None, waiting=False):
        self.number += 1
        lock = lock or 1000000 + int(uuid.uuid4().hex[:6], 16)
        path = self.area / (self.id().split('.')[-1] + '-' + str(self.number) + '.json')
        log = path.with_suffix('.log').open('wb')
        self.addCleanup(log.close)
        child = subprocess.Popen([sys.executable, str(HELPER), 'hold', '--state', str(path),
            '--label', 'cratectl-barrier-test-' + self.run_id + '-' + str(self.number),
            '--lock', str(lock)], env=self.env, stdout=log, stderr=subprocess.STDOUT)
        self.holders.append((child, path))
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if child.poll() is not None:
                self.fail('Timing helper exited; inspect ' + str(path.with_suffix('.log')))
            if path.exists():
                state = json.loads(path.read_text())
                if state['status'] == ('waiting' if waiting else 'ready'):
                    return child, path, state
            time.sleep(.05)
        self.fail('Timing helper did not reach the requested observed state')

    def assert_released(self, path, state):
        self.assertEqual(json.loads(path.read_text())['status'], 'closed')
        backend = state['backend']
        self.assertEqual(self.sql('SELECT count(*) FROM pg_stat_activity WHERE pid='
            + str(backend['pid']) + " AND backend_start='" + backend['backend_start']
            + "'::timestamptz"), '0')
        self.assertEqual(self.sql('SELECT pg_try_advisory_lock(' + str(state['lock']) + ')'), 't')

    def test_term_releases_backend_and_lock_with_idempotent_close(self):
        child, path, state = self.start()
        self.assertEqual(self.sql('SELECT pg_try_advisory_lock(' + str(state['lock']) + ')'), 'f')
        child.terminate()
        self.assertEqual(child.wait(timeout=10), 0)
        self.assert_released(path, state)
        self.command('close', path)
        self.command('close', path)
        self.assert_released(path, state)

    def test_killed_controller_recovers_its_exact_backend(self):
        child, path, state = self.start()
        child.kill()
        child.wait(timeout=5)
        self.command('close', path)
        self.assert_released(path, state)

    def test_waiting_helper_cannot_release_another_holder(self):
        owner, owner_path, held = self.start()
        waiter, waiter_path, waiting = self.start(lock=held['lock'], waiting=True)
        waiter.terminate()
        self.assertEqual(waiter.wait(timeout=10), 0)
        self.assertEqual(json.loads(waiter_path.read_text())['status'], 'closed')
        self.assertIsNone(owner.poll())
        self.assertEqual(self.sql('SELECT pg_try_advisory_lock(' + str(held['lock']) + ')'), 'f')
        self.assertEqual(self.sql('SELECT count(*) FROM pg_stat_activity WHERE pid='
            + str(waiting['backend']['pid'])), '0')
        owner.terminate()
        self.assertEqual(owner.wait(timeout=10), 0)
        self.assert_released(owner_path, held)

    def test_substituted_pid_and_start_time_terminate_no_session(self):
        owner, path, state = self.start()
        decoy, decoy_path, other = self.start()
        original = path.read_bytes()
        try:
            for backend in [dict(state['backend'], pid=other['backend']['pid']),
                            dict(state['backend'], backend_start=other['backend']['backend_start']),
                            other['backend']]:
                with self.subTest(backend=backend):
                    path.write_text(json.dumps(dict(state, backend=backend)))
                    self.command('close', path, ok=False)
                    self.assertIsNone(owner.poll())
                    self.assertIsNone(decoy.poll())
                    for row in [state, other]:
                        self.assertEqual(self.sql('SELECT pg_try_advisory_lock(' + str(row['lock']) + ')'), 'f')
        finally:
            path.write_bytes(original)
        owner.terminate()
        self.assertEqual(owner.wait(timeout=10), 0)
        self.assert_released(path, state)
        decoy.terminate()
        self.assertEqual(decoy.wait(timeout=10), 0)
        self.assert_released(decoy_path, other)

    def test_recovery_before_backend_identity_was_saved(self):
        child, path, state = self.start()
        child.kill()
        child.wait(timeout=5)
        interrupted = dict(state, status='starting')
        interrupted.pop('backend')
        path.write_text(json.dumps(interrupted))
        self.command('close', path)
        self.assert_released(path, state)

    def test_wrong_destination_and_private_state_guards_preserve_holder(self):
        child, path, state = self.start()
        for key, value in [('PGDATABASE', 'cratectl'), ('PGDATABASE', 'cratectl_other_fixture'),
                           ('PGHOST', '192.0.2.1'), ('PGPORT', '5432')]:
            with self.subTest(key=key, value=value):
                self.command('close', path, env=dict(self.env, **{key: value}), ok=False)
                self.assertIsNone(child.poll())
        path.chmod(0o644)
        try:
            self.command('close', path, ok=False)
        finally:
            path.chmod(0o600)
        self.command('close', ROOT / '.cache/not-private-timing.json', ok=False)
        self.assertEqual(self.sql('SELECT pg_try_advisory_lock(' + str(state['lock']) + ')'), 'f')


if __name__ == '__main__':
    unittest.main(verbosity=2)
