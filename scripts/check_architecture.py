# SPDX-License-Identifier: BUSL-1.1
import pathlib,re,sys
errors=[]
for root in ('internal','cmd','pkg'):
 for p in pathlib.Path(root).rglob('*.go'):
  text=p.read_text()
  if root!='pkg' and 'SPDX-License-Identifier: BUSL-1.1' not in text: errors.append(f'{p}: missing license identifier')
  if p.parent!=pathlib.Path('internal/crypto') and re.search(r'"(?:crypto/[^\"]+|hash/[^\"]+)"',text): errors.append(f'{p}: crypto outside boundary')
  if re.search(r'"[^\"]*/ee(?:/|\")',text): errors.append(f'{p}: core imports ee')
  if p.parent==pathlib.Path('internal/server') and re.search(r'"os/exec"',text):errors.append(f'{p}: registry HTTP process may not invoke package/build execution')
for table in ['tenants','repositories','artifacts','events','mutations','jobs','uploads','tags','repository_grants','retrievals','content_decisions','npm_tags','npm_sources','native_sources','python_yanks','queue_policies','event_projections','integrity_observations','upload_parts','sweep_items','inventory_entries','inventory_observations','bootstrap_receipts','artifact_lifecycle','repository_lifecycle','repository_configurations','integrity_schedules','integrity_schedule_revisions','integrity_schedule_runs','retention_policies','retention_revisions','retention_runs','retention_items','retention_observations']:
 if f'"{table}"' not in pathlib.Path('internal/store/store.go').read_text():errors.append(f'{table}: missing forced RLS migration')
if errors: print('\n'.join(errors));sys.exit(1)
print('PASS: crypto imports, core-only dependency boundary, license IDs and tenant-table RLS declarations')
