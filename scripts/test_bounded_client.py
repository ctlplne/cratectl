#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import os
import io
import json
import selectors
import signal
import subprocess
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from bounded_client import ClientLimitError, run_owned_client, _wait_for_owned_group_removal, _owned_client_exit_code


class BoundedClient(unittest.TestCase):
    def test_exit_observation_keeps_owned_session_leader_reserved_until_reaped(self):
        process=subprocess.Popen([sys.executable,'-c','import sys;sys.exit(7)'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+3
            code=None
            while code is None and time.monotonic()<deadline:
                code=_owned_client_exit_code(process)
                if code is None:time.sleep(.01)
            self.assertEqual(code,7)
            self.assertIsNone(process.returncode)
            # Darwin's getpgid excludes zombies; signal zero still recognizes
            # this unreaped PID, and another WNOWAIT observes the same child.
            os.kill(process.pid,0)
            self.assertEqual(_owned_client_exit_code(process),7)
        finally:
            if _owned_client_exit_code(process) is None:os.killpg(process.pid,signal.SIGKILL)
            self.assertEqual(process.wait(timeout=3),7)

    def test_denied_group_cleanup_requires_observed_removal_without_another_kill(self):
        calls=[]
        def disappearing(group,sig):
            calls.append((group,sig))
            if len(calls)==1: raise PermissionError('synthetic zombie-only group')
            raise ProcessLookupError('group removed')
        with patch('bounded_client.os.killpg',side_effect=disappearing),patch('bounded_client.time.sleep'):
            self.assertTrue(_wait_for_owned_group_removal(12345))
        self.assertEqual(calls,[(12345,0),(12345,0)])

    def test_live_or_still_denied_group_is_not_successful_cleanup(self):
        for outcome in [None,PermissionError('synthetic live denied group')]:
            with self.subTest(denied=outcome is not None),patch('bounded_client.os.killpg',side_effect=outcome),patch('bounded_client.time.monotonic',side_effect=[0,4]):
                self.assertFalse(_wait_for_owned_group_removal(12345))

    def test_denied_final_kill_preserves_result_only_after_group_removal(self):
        real_killpg=os.killpg; calls=[]
        def delayed_removal(group,sig):
            calls.append(sig)
            if sig==signal.SIGKILL:raise PermissionError('synthetic zombie-only final group')
            return real_killpg(group,sig)
        with tempfile.TemporaryDirectory(prefix='cratectl-client-group-removal-') as directory,patch('bounded_client.os.killpg',side_effect=delayed_removal):
            code,output=run_owned_client([sys.executable,'-c','print("owned result")'],directory,dict(os.environ))
        self.assertEqual((code,output),(0,'owned result\n'))
        self.assertEqual(calls,[signal.SIGTERM,signal.SIGKILL,0])

    def test_unconfirmed_group_removal_propagates_the_final_kill_denial(self):
        real_killpg=os.killpg
        def denied(group,sig):
            if sig==signal.SIGKILL:raise PermissionError('owned cleanup remains unconfirmed')
            return real_killpg(group,sig)
        with tempfile.TemporaryDirectory(prefix='cratectl-client-group-denied-') as directory,patch('bounded_client.os.killpg',side_effect=denied),patch('bounded_client._wait_for_owned_group_removal',return_value=False):
            with self.assertRaisesRegex(PermissionError,'unconfirmed'):
                run_owned_client([sys.executable,'-c','print("owned result")'],directory,dict(os.environ))

    def test_parent_exit_after_selector_timeout_drains_complete_private_output(self):
        # The real child writes and exits after the deliberately empty readiness
        # snapshot. Do not mock the pipe, bytes, child exit or private input.
        process=[]; real_popen=subprocess.Popen; real_selector=selectors.DefaultSelector
        class DelayedReadiness:
            def __init__(self): self.selector=real_selector(); self.first=True
            def __enter__(self): return self
            def __exit__(self,*args): self.selector.close()
            def register(self,*args): return self.selector.register(*args)
            def unregister(self,*args): return self.selector.unregister(*args)
            def select(self,timeout):
                if self.first:
                    self.first=False; process[0].wait(timeout=3); return []
                return self.selector.select(timeout)
        def start(*args,**kwargs):
            child=real_popen(*args,**kwargs); process.append(child); return child
        with tempfile.TemporaryDirectory(prefix='cratectl-client-final-output-') as directory:
            for limit in [4096,8]:
                with self.subTest(limit=limit),patch('bounded_client.subprocess.Popen',side_effect=start),patch('bounded_client.selectors.DefaultSelector',DelayedReadiness):
                    process.clear(); sink=io.BytesIO()
                    argv=[sys.executable,'-c','import json;print(json.dumps({"owned":"final private output"}))']
                    if limit==8:
                        with self.assertRaisesRegex(ClientLimitError,'output budget'):
                            run_owned_client(argv,directory,dict(os.environ),output_sink=sink,output_limit=limit)
                        self.assertEqual(sink.getvalue(),b'')
                    else:
                        code,output=run_owned_client(argv,directory,dict(os.environ),output_sink=sink,output_limit=limit)
                        self.assertEqual(code,0)
                        self.assertEqual(json.loads(output),{'owned':'final private output'})
                        self.assertEqual(sink.getvalue().decode(),output)

    def test_deadline_keeps_bounded_private_output_and_polls_control(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-browser-client-') as directory:
            output=io.BytesIO();polls=[]
            with self.assertRaisesRegex(ClientLimitError,'unconfirmed'):
                run_owned_client([sys.executable,'-c','import time;print("owned browser progress",flush=True);time.sleep(30)'],directory,dict(os.environ),timeout=.25,poll_hook=lambda:polls.append(True),output_sink=output)
            self.assertEqual(output.getvalue(),b'owned browser progress\n')
            self.assertGreater(len(polls),1)

    def test_control_failure_still_stops_owned_descendants(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-browser-control-') as directory:
            marker=Path(directory)/'late-child';ready=Path(directory)/'ready'
            child='import time,signal;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(.6);Path('+repr(str(marker))+').touch()'
            parent='import subprocess,sys,time;from pathlib import Path;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);Path('+repr(str(ready))+').touch();time.sleep(30)'
            def control():
                if ready.exists():raise RuntimeError('owned control failed')
            with self.assertRaisesRegex(RuntimeError,'owned control failed'):
                run_owned_client([sys.executable,'-c',parent],directory,dict(os.environ),poll_hook=control)
            time.sleep(.7)
            self.assertFalse(marker.exists())

    def test_output_budget_also_bounds_the_private_sink(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-browser-output-') as directory:
            output=io.BytesIO()
            with self.assertRaisesRegex(ClientLimitError,'output budget'):
                run_owned_client([sys.executable,'-c','import sys,time;sys.stdout.write("x"*10000);sys.stdout.flush();time.sleep(30)'],directory,dict(os.environ),output_limit=1024,output_sink=output)
            self.assertLessEqual(len(output.getvalue()),1024)

    def test_large_structured_result_is_complete_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            code, output=run_owned_client([sys.executable,'-c','import json;print(json.dumps({"owned":"x"*200000}))'],directory,dict(os.environ),capture_limit=8<<20)
            self.assertEqual(code,0)
            self.assertEqual(json.loads(output),{'owned':'x'*200000})

    def test_bounded_private_input_is_exact_and_absence_is_eof(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            program='import json,os,sys;print(json.dumps({"value":sys.stdin.read(),"mode":os.fstat(0).st_mode&0o777}))'
            for value in [None,'owned-standin-password\n', '\u00e9'*1024]:
                code, output=run_owned_client([sys.executable,'-c',program],directory,dict(os.environ),input_text=value)
                self.assertEqual(code,0)
                self.assertEqual(json.loads(output),{'value':value or '', 'mode':0o600})

    def test_oversized_input_and_unbounded_capture_fail_before_spawn(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            marker=Path(directory)/'spawned'
            argv=[sys.executable,'-c','from pathlib import Path;Path('+repr(str(marker))+').touch()']
            for options in [{'input_text':'x'*((1<<20)+1)},{'input_text':'\u00e9'*(1<<20)},
                            {'input_text':b'not-text'},{'capture_limit':(8<<20)+1},{'capture_limit':0}]:
                with self.subTest(options=list(options)),self.assertRaises(ValueError):
                    run_owned_client(argv,directory,dict(os.environ),**options)
            self.assertFalse(marker.exists())

    def test_nonzero_result_and_bounded_tail_are_not_success(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            code, output = run_owned_client([sys.executable, '-c', 'import sys;print("owned"*20000);sys.exit(7)'], directory, dict(os.environ))
            self.assertEqual(code, 7)
            self.assertEqual(len(output), 65536)

    def test_deadline_stops_owned_descendants(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            marker = Path(directory) / 'late-child'
            program = 'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",' + repr('import time,signal;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(.6);Path(' + repr(str(marker)) + ').write_text("unexpected")') + ']);time.sleep(30)'
            with self.assertRaisesRegex(ClientLimitError, 'unconfirmed'):
                run_owned_client([sys.executable, '-c', program], directory, dict(os.environ), timeout=.2)
            time.sleep(.7)
            self.assertFalse(marker.exists(), 'owned descendant outlived cancellation')

    def test_successful_parent_exit_stops_children_holding_output_open(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            marker=Path(directory)/'late-child'
            child='import time,signal;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(.6);Path('+repr(str(marker))+').write_text("unexpected")'
            parent='import subprocess,sys;subprocess.Popen([sys.executable,"-c",'+repr(child)+']);print("owned-parent-finished")'
            code,output=run_owned_client([sys.executable,'-c',parent],directory,dict(os.environ),timeout=2)
            self.assertEqual(code,0)
            self.assertEqual(output.strip(),'owned-parent-finished')
            time.sleep(.7)
            self.assertFalse(marker.exists(),'child holding the output pipe outlived successful parent')

    def test_output_budget_is_a_failure(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            with self.assertRaisesRegex(ClientLimitError, 'output budget'):
                run_owned_client([sys.executable, '-c', 'import sys,time;sys.stdout.write("x"*10000);sys.stdout.flush();time.sleep(30)'], directory, dict(os.environ), output_limit=1024)


if __name__ == '__main__':
    unittest.main()
