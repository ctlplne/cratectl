# SPDX-License-Identifier: BUSL-1.1
"""Offline rule regression: benign synthetic strings, never live credentials."""
import datetime,hashlib,json,subprocess,re,os
from pathlib import Path
root=Path(__file__).resolve().parents[1]
stamp=datetime.datetime.now(datetime.timezone.utc)
base=root/'.cache/secret-rule-fixtures'/stamp.strftime('%Y%m%dT%H%M%S%fZ');base.mkdir(parents=True)
url=re.search(r'https://go\.googlesource\.com/go/\+/[a-f0-9]{40}', (root/'evidence/2026-10-28/govulncheck-first.json').read_text()).group(0)
historical_commit=json.loads((root/'evidence/2026-10-28/gitleaks-history.json').read_text())[0]['Commit']
synthetic='sgp_'+hashlib.sha256(b'not a credential; detector regression only').hexdigest()[:40]
cases=[('public-reference','evidence/2026-10-28/govulncheck.json','"url": "'+url+'"',False),
 ('synthetic-token-same-file','evidence/2026-10-28/govulncheck.json','"token": "'+synthetic+'"',True),
 ('outside-evidence','source.txt','"token": "'+synthetic+'"',True),
 ('scanner-report-commit','evidence/2026-10-28/gitleaks-history.json','"Commit": "'+historical_commit+'"',False),
 ('scanner-report-token','evidence/2026-10-28/gitleaks-history.json','"token": "'+synthetic+'"',True),
 ('url-query','evidence/2026-10-28/govulncheck.json','"url": "'+url+'?token='+synthetic+'"',True)]
for repository in ['go','net','text','pgx','pgproto3']:
 for stream in ['go-symbol-vulnerability','binary-symbol-cratectld','binary-symbol-cratectl']:
  name=repository+'-'+stream
  path='evidence/2026-10-31/retention-schedule-'+stream+'.jsonl'
  reference=url.replace('/go/+/','/'+repository+'/+/')if repository in ['go','net','text']else'https://github.com/jackc/'+repository+'/commit/'+url.rsplit('/',1)[1]
  wrong_host=reference.replace('go.googlesource.com','example.invalid').replace('github.com','example.invalid')
  assert wrong_host!=reference
  cases.extend([
  (name+'-public-reference',path,'"url": "'+reference+'"',False),
  (name+'-prefixed-token',path,'"token": "'+synthetic+'"',True),
  (name+'-bare-token',path,'"token": "'+synthetic[4:]+'"',True),
  (name+'-other-field',path,'"notes": "'+reference+'"',True),
  (name+'-query',path,'"url": "'+reference+'?token='+synthetic+'"',True),
  (name+'-fragment',path,'"url": "'+reference+'#token='+synthetic+'"',True),
  (name+'-userinfo',path,'"url": "'+reference.replace('https://','https://user@')+'"',True),
  (name+'-other-host',path,'"url": "'+wrong_host+'"',True),
  (name+'-other-file',path+'.txt','"url": "'+reference+'"',True),
 ])
review_path='evidence/2026-10-31/retention-schedule-secret-rule-preflight.json'
review_parent=json.loads((root/review_path).read_text())['source_parent']
cases.extend([
 ('public-review-parent',review_path,'"source_parent": "'+review_parent+'"',False),
 ('review-prefixed-token',review_path,'"source_parent": "'+synthetic+'"',True),
 ('review-bare-token',review_path,'"source_parent": "'+synthetic[4:]+'"',True),
 ('review-other-field',review_path,'"token": "'+review_parent+'"',True),
 ('review-other-file','evidence/2026-10-31/other-review.json','"source_parent": "'+review_parent+'"',True),
])
history_path='evidence/2026-10-31/retention-schedule-postcommit-history-first-failure.json'
history_parent=json.loads((root/history_path).read_text())[0]['Commit']
cases.extend([
 ('public-history-commit',history_path,'"Commit": "'+history_parent+'"',False),
 ('history-prefixed-token',history_path,'"Commit": "'+synthetic+'"',True),
 ('history-bare-token',history_path,'"Commit": "'+synthetic[4:]+'"',True),
 ('history-other-field',history_path,'"token": "'+history_parent+'"',True),
 ('history-other-file','evidence/2026-10-31/other-history.json','"Commit": "'+history_parent+'"',True),
])
results=[]
for name,path,text,expected in cases:
 # The rule's keyword must be present even for a public/bare 40-hex value.
 # Otherwise a benign URL could pass without exercising the exception at all.
 d=base/name;f=d/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('sourcegraph regression context\n'+text+'\n')
 native=os.environ.get('CRATECTL_GITLEAKS_BIN')
 # Each ignored fixture has one local commit, always under the owner's identity.
 identity=dict(os.environ,GIT_AUTHOR_NAME='imfeelingtheagi',GIT_AUTHOR_EMAIL='288773099+imfeelingtheagi@users.noreply.github.com',GIT_COMMITTER_NAME='imfeelingtheagi',GIT_COMMITTER_EMAIL='288773099+imfeelingtheagi@users.noreply.github.com')
 subprocess.run(['git','init','-q','-b','main',str(d)],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 subprocess.run(['git','add','--',path],cwd=d,check=True)
 subprocess.run(['python3',str(root/'scripts/check_commit_identity.py')],cwd=d,env=identity,check=True)
 subprocess.run(['git','-c','commit.gpgsign=false','commit','-q','-m','Synthetic secret-detector fixture'],cwd=d,env=identity,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 for mode in ['dir','git']:
  command=[native,mode,str(d),'--config',str(root/'.gitleaks.toml'),'--no-banner','--redact'] if native else ['docker','run','--rm','--network','none','--name','cratectl-secret-rule-'+mode+'-'+name,'--label','ctlplne.project=cratectl','--memory','256m','-v',str(d)+':/scan:ro','-v',str(root/'.gitleaks.toml')+':/rules.toml:ro','c00b6bd0aeb3',mode,'/scan','--config','/rules.toml','--no-banner','--redact']
  result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  (d/('scanner-output-'+mode+'.txt')).write_text(result.stdout)
  observed=result.returncode==1
  results.append({'case':name+'-'+mode,'mode':mode,'expected_finding':expected,'observed_finding':observed,'exit':result.returncode,'passed':result.returncode in [0,1]and observed==expected})
report=Path(os.environ.get('CRATECTL_SECRET_RULE_REPORT',str(root/'evidence'/stamp.date().isoformat()/'gitleaks-rule-fixtures.json')))
report.parent.mkdir(parents=True,exist_ok=True)
data={'scanner':'gitleaks v8.30.1','source_parent':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--','.gitleaks.toml','scripts/test_secret_rules.py'],cwd=root,text=True).strip()),'rules_sha256':hashlib.sha256((root/'.gitleaks.toml').read_bytes()).hexdigest(),'fixture_driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'fixture_logs':str(base.relative_to(root)),'results':results,'passed':all(r['passed']for r in results)}
report.write_text(json.dumps(data,indent=2)+'\n')
if not data['passed']:raise SystemExit('Rule regression failed: '+', '.join(r['case']for r in results if not r['passed'])+'; retained '+str(report))
print('PASS: '+str(len(results))+' narrow-reference and credential counterexamples; '+str(report))
