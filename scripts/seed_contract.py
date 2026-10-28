# SPDX-License-Identifier: BUSL-1.1
"""Create the initial contract once; never overwrite execution evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/qualification'
DATE = '2026-10-28'
SOURCES = {
    'nexus-formats': ('https://help.sonatype.com/en/formats.html', 'Nexus Repository CE/Pro/Pro+', '3.97.3'),
    'nexus-features': ('https://help.sonatype.com/en/nexus-repository-feature-matrix.html', 'Nexus Repository CE/Pro/Pro+ and Firewall', '3.97.3'),
    'jfrog-formats': ('https://docs.jfrog.com/artifactory/docs/supported-package-types', 'Artifactory paid self-managed', None),
    'jfrog-features': ('https://docs.jfrog.com/installation/docs/feature-comparison-matrix-for-self-mangaged-jpds', 'JFrog Pro X/Enterprise X/Enterprise+', None),
    'apptrust': ('https://docs.jfrog.com/governance/docs/jfrog-apptrust', 'JFrog AppTrust', None),
    'harbor': ('https://goharbor.io/docs/2.15.0/', 'Harbor', '2.15.0'),
    'pulp': ('https://pulpproject.org/', 'Pulp and format plugins', None),
    'owner': ('GOAL.md', 'Owner committed scope', None),
}
# Equivalent client names share a protocol row; they do not inflate format coverage.
FORMATS = {
 'oci': ['docker','podman','oras','helm OCI','buildctl','buildx','WASM OCI'],
 'maven': ['mvn','gradle','ivy','sbt'], 'npm': ['npm','pnpm','yarn'],
 'pypi': ['pip','uv','twine','poetry'], 'nuget': ['dotnet','nuget','chocolatey','powershell'],
 'go': ['go'], 'cargo': ['cargo'], 'apt': ['apt-get'], 'rpm': ['dnf','yum'],
 'apk': ['apk'], 'opkg': ['opkg'], 'helm-http': ['helm'], 'conan': ['conan 1','conan 2'],
 'composer': ['composer 2'], 'rubygems': ['gem','bundler'], 'conda': ['conda'],
 'cran': ['R'], 'cocoapods': ['pod'], 'swift': ['swift','Xcode'], 'pub': ['dart','flutter'],
 'terraform': ['terraform','tofu'], 'ansible': ['ansible-galaxy'], 'chef': ['knife'],
 'puppet': ['puppet'], 'vagrant': ['vagrant'], 'p2': ['eclipse'], 'bower': ['bower'],
 'hex': ['mix'], 'bazel': ['bazel'], 'git-lfs': ['git-lfs'],
 'huggingface': ['huggingface_hub'], 'generic': ['curl'], 'agent-plugins': ['documented agent clients'],
 'ai-editor-extensions': ['VS Code','Cursor','Kiro','Devin'], 'jetbrains': ['JetBrains IDE'],
 'luarocks': ['luarocks'], 'nix': ['nix'], 'nvidia': ['documented NVIDIA clients'],
 'ml-repository': ['documented ML clients'], 'vcs': ['git'], 'skills': ['documented skill clients'],
}
NEXUS = set('oci maven npm pypi nuget go cargo apt rpm apk helm-http conan composer rubygems conda cran cocoapods swift pub terraform ansible p2 bower git-lfs huggingface generic'.split())
MODES = {
 'apt': {'hosted':True,'proxy':True,'group':False},
 'bower': {'hosted':False,'proxy':False,'group':False},
 'cocoapods': {'hosted':False,'proxy':True,'group':False},
 'git-lfs': {'hosted':True,'proxy':False,'group':False},
 'huggingface': {'hosted':False,'proxy':True,'group':False},
 'p2': {'hosted':False,'proxy':True,'group':False},
}
DOMAINS = {
 'REPO': 'templates properties labels ownership selectors search precedence namespace-ownership dependency-confusion cache-freshness negative-cache stale-policy retention holds archive restore tiers delete repair gc bulk-preview bulk-cancel client-config'.split(),
 'AUTH': 'oidc saml ldap scim emergency-access mfa passkey service-tokens rotation revocation content-permissions provider-exception'.split(),
 'SEC': 'sbom-spdx sbom-cyclonedx vex signatures provenance vulnerabilities licenses maturity malicious-content secrets code-analysis reachability waivers rescan reverse-impact offline-intelligence corpus-fp-fn scanner-isolation'.split(),
 'RELEASE': 'build-info ci-identities dependency-graphs cosign notation intoto slsa private-trust offline-verify immutable-manifest stages approvals separation-of-duties promotion rollback monitoring evidence-export'.split(),
 'DIST': 'signed-bundles resumable integrity acknowledgments rate-limits rollout withdrawal disconnected edge'.split(),
 'STATE': 'postgres-rls journal publication idempotency outbox leases bounded-queues fairness projections audit-chain'.split(),
 'STORE': 'filesystem s3 multipart quotas encryption customer-keys versioning retention-lock integrity reconciliation backup restore gc-safety'.split(),
 'OPS': 'single-node cluster replication-push replication-pull federation-conflicts loop-protection failover partitions rpo-rto upgrade recovery observability otel'.split(),
 'MIGRATE': 'nexus artifactory harbor pulp inventory dry-run incremental checkpoints cutover rollback export inventory-verification'.split(),
 'UX': 'blank-install console api cli declarative terraform-provider mcp accessibility empty-error-recovery'.split(),
 'QUAL': 'unit integration race fuzz frontend conformance security dependency-scan secret-scan image-scan sbom provenance packaging linux-amd64 linux-arm64 macos windows offline-install standard-profile large-profile soak24h performance-cost paid-comparison'.split(),
 'LEGAL': ['grant','core-no-entitlements','client-mpl','ee-boundary'],
}

def write(name, value):
    path=OUT/name
    if path.exists():
        raise SystemExit(f'Refusing to replace existing ledger: {path}')
    path.write_text(json.dumps(value, indent=2)+'\n')

rows=[]
formats=[]
for fmt, clients in FORMATS.items():
    sources=['jfrog-formats'] + (['nexus-formats'] if fmt in NEXUS else []) + ['owner']
    formats.append({'id':fmt,'clients':clients,'client_versions':{},'source_ids':sources,
      'nexus_modes':MODES.get(fmt, {m:True for m in ['hosted','proxy','group']}) if fmt in NEXUS else None,
      'jfrog_modes':'per-format documentation review required',
      'native_limitations': 'Bower unsupported with current Nexus databases; JFrog workflow still required.' if fmt=='bower' else 'Mode-specific limits must be established before claiming coverage.',
      'state':'planned'})
    for op in ['hosted','proxy','group','replication','search','authorization','lifecycle']:
        cid=f'FMT.{fmt.upper()}.{op.upper()}'
        rows.append({'id':cid,'customer_job':f'{op} {fmt} packages with ordinary clients',
          'protocol_operation':op, 'format':fmt, 'source_ids':sources,
          'baseline':[{'product':SOURCES[s][1],'edition':SOURCES[s][1],'version':SOURCES[s][2], 'url':SOURCES[s][0], 'observed_on':DATE} for s in sources],
          'implementation':None,'surfaces':{'api':None,'cli':None,'ui':None}, 'core':True,
          'dependencies':['tenant authorization','durable publication','current policy'],
          'acceptance_journey':f'J.{fmt.upper()}.{op.upper()}', 'clients':clients,'client_versions':{},
          'test_data':'Two nontrivial versions plus a dependency package; same coordinates in two tenants.',
          'permission_cases':['reader denial on publish','revoked token','underlying group access','tenant collision'],
          'failure_cases':['restart','interrupted transfer','concurrency','policy denial','upstream outage','delete/restore'],
          'state':'planned','candidate':None,'evidence':[],'limits':'No implementation or native-client proof yet.',
          'next_action':f'Implement {fmt} {op} and execute the complete stock-client journey.'})
for domain, jobs in DOMAINS.items():
    for job in jobs:
        cid=f'{domain}.{job.upper()}'
        sid='apptrust' if domain=='RELEASE' else 'nexus-features' if domain in ['AUTH','REPO'] else 'jfrog-features' if domain in ['SEC','DIST','STORE','OPS'] else 'owner'
        rows.append({'id':cid,'customer_job':job.replace('-',' '),'protocol_operation':job,'format':None,
          'source_ids':[sid,'owner'] if sid!='owner' else ['owner'],
          'baseline':[{'product':SOURCES[sid][1],'edition':SOURCES[sid][1],'version':SOURCES[sid][2], 'url':SOURCES[sid][0], 'observed_on':DATE}],
          'implementation':None,'surfaces':{'api':None,'cli':None,'ui':None},'core':True,
          'dependencies':[],'acceptance_journey':f'J.{cid}','clients':[],'client_versions':{},
          'test_data':'Defined by the corresponding GOAL.md acceptance requirement.',
          'permission_cases':['least privilege','tenant collision','revocation'],
          'failure_cases':['restart','concurrent mutation','partial failure','recovery'],
          'state':'planned','candidate':None,'evidence':[],'limits':'Not implemented or qualified.',
          'next_action':'Specify and implement the owner-required journey, then retain observed evidence.'})
write('sources.json',{'observed_on':DATE,'sources':{k:{'url':v[0],'product':v[1],'version':v[2]} for k,v in SOURCES.items()},
 'version_notes':['Nexus 3.97.3 observed in official version status (2026-10-27 release).',
 'JFrog self-managed landing page did not expose an exact current patch; no patch guessed. Follow release links before hands-on comparison.',
 'Pulp core/plugin versions must be pinned separately before comparison.',
 'Nexus Bower limitations differ from cross-vendor union; keep the JFrog workflow open.',
 'JFrog formats add LuaRocks, Nix, NVIDIA, VCS, ML repositories, Skills beta and editor feeds; retained as open rows.'],
 'comparison_state':'Documentary baseline only; no paid hands-on comparison has run.'})
write('formats.json',{'formats':formats})
write('parity.json',{'schema_version':1,'observed_on':DATE,'capabilities':rows})
write('journeys.json',{'journeys':[{'id':r['acceptance_journey'],'capability':r['id'],'state':'planned','candidate':None,'evidence':[],'required':['publish/consume exact bytes where applicable','permissions/tenant isolation','policy denial','failure/recovery']} for r in rows]})
write('remaining.json',{'goal_complete':False,'readiness':{'assisted_design_partner':'not qualified','ordinary_operator':'not qualified','enterprise':'not qualified'},
 'next':['Establish first-failure native npm/PyPI/OCI/Maven tests.','Implement and verify tenant-scoped durable publication on real PostgreSQL.','Complete remaining Stage 1 journeys before expanding format implementations.'],
 'external_inputs':[{'id':'LEGAL.GRANT','input':'Owner-approved cratectl Additional Use Grant before distribution','blocks':'Distribution only; local engineering continues'},
 {'id':'QUAL.PAID-COMPARISON','input':'Licensed self-managed benchmark systems','blocks':'Hands-on comparator evidence only'},
 {'id':'QUAL.LARGE-PROFILE','input':'Independent hosts and standard/large capacity','blocks':'Scale/multi-host qualification only'},
 {'id':'QUAL.WINDOWS','input':'Native Windows runtime','blocks':'Native Windows qualification only'}],
 'unfinished_capabilities':[r['id'] for r in rows]})
write('defects.json',{'defects':[]})
print(f'Created {len(rows)} capability/journey rows and {len(formats)} protocol families; all planned.')
