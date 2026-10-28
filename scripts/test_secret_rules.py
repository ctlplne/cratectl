# SPDX-License-Identifier: BUSL-1.1
"""Offline rule regression: benign synthetic strings, never live credentials."""
import hashlib,json,subprocess,re,os
from pathlib import Path
root=Path(__file__).resolve().parents[1]
base=root/'.cache/secret-rule-fixtures';base.mkdir(exist_ok=True)
url=re.search(r'https://go\.googlesource\.com/go/\+/[a-f0-9]{40}', (root/'evidence/2026-10-28/govulncheck-first.json').read_text()).group(0)
historical_commit=json.loads((root/'evidence/2026-10-28/gitleaks-history.json').read_text())[0]['Commit']
synthetic='sgp_'+hashlib.sha256(b'not a credential; detector regression only').hexdigest()[:40]
cases=[('public-reference','evidence/2026-10-28/govulncheck.json','"url": "'+url+'"',False),
 ('synthetic-token-same-file','evidence/2026-10-28/govulncheck.json','"token": "'+synthetic+'"',True),
 ('outside-evidence','source.txt','"token": "'+synthetic+'"',True),
 ('scanner-report-commit','evidence/2026-10-28/gitleaks-history.json','"Commit": "'+historical_commit+'"',False),
 ('scanner-report-token','evidence/2026-10-28/gitleaks-history.json','"token": "'+synthetic+'"',True),
 ('url-query','evidence/2026-10-28/govulncheck.json','"url": "'+url+'?token='+synthetic+'"',True)]
results=[]
for name,path,text,expected in cases:
 d=base/name;f=d/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text+'\n')
 native=os.environ.get('CRATECTL_GITLEAKS_BIN')
 command=[native,'dir',str(d),'--config',str(root/'.gitleaks.toml'),'--no-banner','--redact'] if native else ['docker','run','--rm','--network','none','--name','cratectl-secret-rule-'+name,'--label','ctlplne.project=cratectl','--memory','256m','-v',str(d)+':/scan:ro','-v',str(root/'.gitleaks.toml')+':/rules.toml:ro','c00b6bd0aeb3','dir','/scan','--config','/rules.toml','--no-banner','--redact']
 result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 observed=result.returncode==1
 if result.returncode not in [0,1] or observed!=expected:raise SystemExit(f'Rule regression failed: {name}, exit {result.returncode}; '+result.stdout)
 results.append({'case':name,'expected_finding':expected,'observed_finding':observed,'exit':result.returncode})
(root/'evidence/2026-10-28/gitleaks-rule-fixtures.json').write_text(json.dumps({'scanner':'gitleaks v8.30.1','results':results},indent=2)+'\n')
print('PASS: narrow public-reference exception and four credential counterexamples')
