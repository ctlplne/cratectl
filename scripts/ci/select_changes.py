#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Select expensive CI only when runtime inputs changed; secret scans stay separate."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bounded_client import run_owned_client

SHA=re.compile('[0-9a-f]{40}')
RUNTIME_DOCS={'docs/qualification/jvm-clients.json','docs/qualification/upgrade-baselines.json','docs/qualification/ci-diagnostics-recipient.pem'}
DOCUMENTATION_DATA={'docs/qualification/'+name+'.json'for name in ['remaining','parity','journeys','formats','defects','sources','jvm-client-plan','go-export-plan']}

def runtime_input(path):
    # Unknown files and malformed names select all checks. Only this narrow
    # documentation/evidence set can avoid a redundant native campaign.
    if not isinstance(path,str)or not path or len(path)>4096 or chr(92)in path or chr(0xfffd)in path or any(ord(c)<32 or ord(c)==127 for c in path):return True
    if path in RUNTIME_DOCS:return True
    if path.startswith('evidence/')or path in DOCUMENTATION_DATA or path in ('README.md','STATUS.md')or path.startswith('docs/')and path.endswith('.md'):return False
    return True

def selection(root,candidate,event_name,event):
    if not isinstance(candidate,str)or not SHA.fullmatch(candidate):raise ValueError('CI selection requires an exact source SHA')
    actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True,timeout=10).strip()
    if actual!=candidate:raise ValueError('CI selection source does not match checkout')
    result={'schema':1,'candidate':candidate,'base':None,'event':event_name if event_name in ('push','pull_request','workflow_dispatch')else 'other','runtime':True,'reason':'unknown_event_full','changed_paths':None,'normalized_path_list_sha256':None,'limits':['Selection is not a test pass. Unselected jobs never count as verified.','The independent scoped source/binary/history/secret job still runs for every event.']}
    if event_name=='workflow_dispatch':result['reason']='manual_full';return result
    if not isinstance(event,dict):result['reason']='invalid_event_full';return result
    if event_name=='push':base=event.get('before')
    elif event_name=='pull_request':
        request=event.get('pull_request');base=request.get('base',{}).get('sha')if isinstance(request,dict)and isinstance(request.get('base',{}),dict)else None
    else:return result
    if not isinstance(base,str)or not SHA.fullmatch(base)or base=='0'*40:result['reason']='unavailable_base_full';return result
    result['base']=base
    try:
        code,output=run_owned_client(['git','diff','--no-ext-diff','--no-textconv','--no-renames','--name-only','-z',base,candidate,'--'],root,dict(os.environ),timeout=30,output_limit=8<<20,capture_limit=8<<20)
    except (OSError,RuntimeError,ValueError):result['reason']='unavailable_diff_full';return result
    if code:result['reason']='unavailable_diff_full';return result
    if output and not output.endswith('\0'):result['reason']='malformed_diff_full';return result
    paths=output.split('\0')
    if paths[-1]=='':paths.pop()
    if len(paths)>100000:result['reason']='path_budget_full';return result
    result['changed_paths']=len(paths)
    result['normalized_path_list_sha256']=hashlib.sha256(json.dumps(paths,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    result['runtime']=any(runtime_input(p)for p in paths)
    result['reason']='runtime_input_change'if result['runtime']else 'documentation_only'if paths else 'no_changes'
    return result

def main():
    root=Path(__file__).resolve().parents[2]
    event={}
    try:
        with open(os.environ['GITHUB_EVENT_PATH'],'rb')as source:raw=source.read((2<<20)+1)
        if len(raw)<=2<<20:event=json.loads(raw)
    except (OSError,KeyError,ValueError):event=None
    result=selection(root,os.environ.get('GITHUB_SHA',''),os.environ.get('GITHUB_EVENT_NAME',''),event)
    out=root/'.cache/ci-selection.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n')
    with open(os.environ['GITHUB_OUTPUT'],'a')as target:target.write('runtime='+str(result['runtime']).lower()+'\n')
    print('CI selection: '+result['reason']+'; runtime='+str(result['runtime']).lower())
if __name__=='__main__':main()
