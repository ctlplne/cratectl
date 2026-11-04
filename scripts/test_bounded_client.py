#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import os
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from bounded_client import ClientLimitError, run_owned_client


class BoundedClient(unittest.TestCase):
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
