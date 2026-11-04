#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import json,os,subprocess,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
from select_changes import runtime_input,selection
ROOT=Path(__file__).resolve().parents[2]
OWNER='imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>'
class ChangeSelection(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='cratectl-ci-selection-',dir=ROOT/'.cache');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  subprocess.run(['git','init','-q','-b','main',str(self.root)],check=True)
  self.environment=dict(os.environ,GIT_AUTHOR_NAME='imfeelingtheagi',GIT_AUTHOR_EMAIL='288773099+imfeelingtheagi@users.noreply.github.com',GIT_COMMITTER_NAME='imfeelingtheagi',GIT_COMMITTER_EMAIL='288773099+imfeelingtheagi@users.noreply.github.com')
  self.write('internal/owned.go','owned source stand-in');self.base=self.commit()
 def write(self,name,value):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
 def commit(self):
  for name in ['GIT_AUTHOR_IDENT','GIT_COMMITTER_IDENT']:
   self.assertTrue(subprocess.check_output(['git','var',name],cwd=self.root,env=self.environment,text=True).startswith(OWNER+' '))
  subprocess.run(['git','add','--all'],cwd=self.root,check=True)
  subprocess.run(['git','commit','-qm','Owned CI selection fixture'],cwd=self.root,env=self.environment,check=True)
  return subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.root,text=True).strip()
 def test_documentation_only_selection_has_no_raw_names(self):
  self.write('docs/qualification/remaining.json','{}');self.write('evidence/owned.json','{}');self.write('STATUS.md','owned status');head=self.commit()
  d=selection(self.root,head,'push',{'before':self.base});self.assertFalse(d['runtime']);self.assertEqual(d['reason'],'documentation_only');self.assertEqual(d['changed_paths'],3);self.assertNotIn('remaining.json',json.dumps(d))
 def test_runtime_inputs_pins_instructions_and_unknown_files_select_full(self):
  for path in ['cmd/owned.go','internal/x.go','scripts/x.py','api/openapi.yaml','web/src/x.tsx','go.mod','Makefile','global.json','.github/workflows/ci.yml','AGENTS.md','GOAL.md','.gitleaks.toml','new-configuration','docs/qualification/jvm-clients.json','docs/qualification/upgrade-baselines.json','docs/qualification/ci-diagnostics-recipient.pem','docs/new-runtime-pins.json','docs/new-certificate.pem']:
   self.assertTrue(runtime_input(path),path)
  self.write('docs/qualification/jvm-clients.json','{}');head=self.commit();self.assertTrue(selection(self.root,head,'push',{'before':self.base})['runtime'])
 def test_runtime_rename_to_docs_cannot_hide_deleted_input(self):
  (self.root/'docs').mkdir();(self.root/'internal/owned.go').rename(self.root/'docs/moved.txt');head=self.commit();d=selection(self.root,head,'push',{'before':self.base});self.assertTrue(d['runtime']);self.assertEqual(d['changed_paths'],2)
 def test_manual_missing_base_unknown_event_and_bad_checkout_never_skip(self):
  self.write('README.md','owned docs');head=self.commit()
  for event,payload in [('workflow_dispatch',{}),('push',{}),('push',{'before':'0'*40}),('push',{'before':'f'*40}),('schedule',{}),('push',None)]:
   with self.subTest(event=event,payload=payload):self.assertTrue(selection(self.root,head,event,payload)['runtime'])
  with self.assertRaises(ValueError):selection(self.root,self.base,'push',{'before':self.base})
  with self.assertRaises(ValueError):selection(self.root,'not-a-sha','push',{})
 def test_pull_request_uses_exact_base_and_malformed_paths_are_conservative(self):
  self.write('docs/owned.md','owned docs');head=self.commit();self.assertFalse(selection(self.root,head,'pull_request',{'pull_request':{'base':{'sha':self.base}}})['runtime'])
  self.assertTrue(selection(self.root,head,'pull_request',{'pull_request':{'base':None}})['runtime'])
  for path in ['',None,'docs/unsafe'+chr(10)+'name.md','docs/unsafe'+chr(92)+'name.md','docs/unsafe'+chr(0xfffd)+'.md']:self.assertTrue(runtime_input(path))
 def test_diff_limits_and_command_failures_select_full(self):
  self.write('docs/owned.md','owned docs');head=self.commit()
  with patch('select_changes.run_owned_client',side_effect=RuntimeError('owned deadline stand-in')):
   self.assertEqual(selection(self.root,head,'push',{'before':self.base})['reason'],'unavailable_diff_full')
  with patch('select_changes.run_owned_client',return_value=(0,'docs/truncated.md')):
   self.assertEqual(selection(self.root,head,'push',{'before':self.base})['reason'],'malformed_diff_full')
  with patch('select_changes.run_owned_client',return_value=(1,'owned git failure')):
   self.assertTrue(selection(self.root,head,'push',{'before':self.base})['runtime'])
if __name__=='__main__':unittest.main()
